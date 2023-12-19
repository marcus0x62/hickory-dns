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

use std::collections::HashMap;
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

pub struct BlockListAuthority {
    origin: LowerName,
    block_table: HashMap<String,bool>, // String: key, bool: wildcard?
    wildcard_match: bool,
    min_wildcard_depth: u8,
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
            wildcard_match: config.wildcard_match,
            min_wildcard_depth: config.min_wildcard_depth,
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

        for entry in contents.split('\n') {
            if entry == "" {
                continue;
            }

            let mut str_entry = entry.to_string();
            if entry.chars().last() != Some('.') {
                str_entry += ".";
            }
            debug!("Inserting blocklist entry {str_entry:?}");
            self.block_table.insert(str_entry, false);
        }

        true
    }

    /// Build a wildcard match list for a given host
    pub fn get_wildcards(&self, host: &str) -> Vec<String> {
        let elems: Vec<&str> = host.split('.').collect();
        let mut wildcards = vec![];

        debug!("minimium wildcard depth: {}", self.min_wildcard_depth);
        for i in 0..elems.len()-(self.min_wildcard_depth as usize + 1) {
            let mut wc = "*".to_string();
            
            for j in i+1..elems.len() {
                wc += ".";
                wc += elems[j];
            }
            debug!("{i}: {wc}");
            wildcards.push(wc);
        }
        wildcards
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

        let mut match_list = vec![name.to_string()];
        if self.wildcard_match == true {
            match_list.append(&mut self.get_wildcards(&name.to_string()));
        }

        debug!("Match list: {match_list:?}");
        for host in match_list {
            if self.block_table.contains_key(&host) {
                info!("Query '{name}' is blocked by blocklist");
                return Ok(BlockListLookup(Lookup::from_rdata(Query::query(name.into(), rtype), RData::A(A::new(0,0,0,0)))));
            }
        }
        debug!("Query '{name}' is not in blocklist; returning NotHandled...");
        return Err(LookupError::NotHandled);
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
