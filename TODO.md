
* add mempool footer verification to libmempool. this shouldn't be
  too expensive, as we just compute the base + mh_len and it should be there.