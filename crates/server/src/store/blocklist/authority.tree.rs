// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{io, path::Path};

use tracing::{debug, info};

use crate::{
    authority::{
        Authority, LookupError, LookupObject, LookupOptions, MessageRequest, UpdateResult, ZoneType,
    },
    proto::{
        op::{Query, ResponseCode},
        rr::{RData, LowerName, Name, Record, RecordType, rdata::A},
    },
    resolver::lookup::Lookup,
    server::RequestInfo,
    store::blocklist::BlockListConfig,
};

use std::collections::{HashMap,BTreeMap};
use std::path::PathBuf;
use std::fs::File;
use std::io::prelude::*;

/// An authority that will resolve queries against one or more block lists.  The typical use case will be to use this in a chained
/// configuration before a forwarding or recursive resolver:
///
///   [[zones]]
///   zone = "."
///   zone_type = "hint"
///   stores = [{ type = "blocklist", lists = ["default/bl.txt", "default/bl2.txt"]}, { type = "recursor", roots = "default/root.zone"}]
///
/// Note: the order of the stores is important: the first one specified in the store list will be the first consulted.  Subsequent stores
/// will only be consulted if each prior store returns Err(LookupError::NotHandled) in response to the query.

#[derive(Debug)]
struct BlockTree {
    entry: String,
    wildcard: bool,
    children: HashMap<String,BlockTree>,
    ptr: Option<&'static BlockTree>,
}

pub struct BlockListAuthority {
    origin: LowerName,
    block_table: HashMap<String,bool>, // String: key, bool: wildcard?
    block_tree: BlockTree,
}

impl BlockTree {
    fn new() -> Self {
        BlockTree {
            entry: ".".to_string(),
            wildcard: false,
            children: HashMap::new(),
            ptr: None,
        }
    }

    fn insert(&mut self, entry: String) {
        let mut host_elements: Vec<&str> = entry.split('.').rev().collect();
        host_elements[0] = ".";

        let mut tree: &mut BlockTree = self;
        tree.ptr = Some(&tree);
        
        for (i, element) in host_elements.iter().enumerate() {
            if i == 0 && *element == "." {
                continue;
            } else if i == 0 {
                debug!("Unknown root element: {element}.  Not inserting {entry} into blocklist!");
                return;
            } else {
                if ! tree.children.contains_key(element.clone()) {
                    tree.children.insert(element.to_string(), BlockTree {entry: element.to_string(), wildcard: false, children: HashMap::new(), ptr: None});
                }
            }
            println!("{i} element: {element}");
        }
        dbg!(self);
    }
}

impl BlockListAuthority {
    /// Read the Authority for the origin from the specified configuration
    pub async fn try_from_config(
        origin: Name,
        _zone_type: ZoneType,
        config: &BlockListConfig,
        root_dir: Option<&Path>,
    ) -> Result<Self, String> {
        info!("loading blocklist config: {}", origin);

        let block_table: HashMap<String,bool> = HashMap::new();
        let mut authority = BlockListAuthority {
            origin: origin.into(),
            block_table: block_table,
            block_tree: BlockTree::new()
        };

        // Load block lists into the block table cache for this authority.
        for bl in &config.lists {
            info!("Adding blocklist {bl:?}");
            authority.add(format!("{}/{bl}", root_dir.unwrap().display()));
        }

        Ok(authority)
    }

    /// Add a configured block list to the in-memory cache.
    pub fn add(&mut self, file: String) -> bool {
        let mut handle = File::open(file).expect("unable to open block list file");
        let mut contents = String::new();
        let _ = handle.read_to_string(&mut contents);

        for line in contents.split('\n') {
            if line == "" {
                continue;
            }

            debug!("Inserting blocklist entry {line:?}");
            self.block_tree.insert(line.to_string().clone());
            self.block_table.insert(line.to_string().clone(), true);
        }

        true
    }
}

#[async_trait::async_trait]
impl Authority for BlockListAuthority {
    type Lookup = BlockListLookup;

    /// Always Recursive
    fn zone_type(&self) -> ZoneType {
        ZoneType::Hint
    }

    /// Always false for Forward zones
    fn is_axfr_allowed(&self) -> bool {
        false
    }

    async fn update(&self, _update: &MessageRequest) -> UpdateResult<bool> {
        Err(ResponseCode::NotImp)
    }

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    ///
    /// In the context of a forwarder, this is either a zone which this forwarder is associated,
    ///   or `.`, the root zone for all zones. If this is not the root zone, then it will only forward
    ///   for lookups which match the given zone name.
    fn origin(&self) -> &LowerName {
        &self.origin
    }

    /// Forwards a lookup given the resolver configuration for this Forwarded zone
    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        _lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        debug!("blocklist lookup: {} {}", name, rtype);

        let query = Query::query(name.into(), rtype);

        if self.block_table.contains_key(&query.name().to_string()[..]) {
            info!("Query '{name}' is blocked by blocklist");

            let lookup = Lookup::from_rdata(query, RData::A(A::new(0,0,0,0)));
            let bl_lookup = BlockListLookup(lookup);

            return Ok(bl_lookup);
        } else {
            debug!("Query '{name}' is not in blocklist; returning NotHandled...");
            return Err(LookupError::NotHandled);
        }
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        self.lookup(
            request_info.query.name(),
            request_info.query.query_type(),
            lookup_options,
        )
        .await
    }

    async fn get_nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        Err(LookupError::from(io::Error::new(
            io::ErrorKind::Other,
            "Getting NSEC records is unimplemented for the blocklist",
        )))
    }
}

pub struct BlockListLookup(Lookup);

impl LookupObject for BlockListLookup {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Record> + Send + 'a> {
        Box::new(self.0.record_iter())
    }

    fn take_additionals(&mut self) -> Option<Box<dyn LookupObject>> {
        None
    }
}
