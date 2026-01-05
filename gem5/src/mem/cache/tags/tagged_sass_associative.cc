#include "mem/cache/tags/tagged_sass_associative.hh"

#include "base/intmath.hh"
#include "crypto/qarma64.h"
#include "mem/cache/replacement_policies/replaceable_entry.hh"

namespace gem5
{

TaggedSassAssociative::TaggedSassAssociative(const Params &p)
  : TaggedIndexingPolicy(p, p.size / p.entry_size, floorLog2(p.entry_size))
{
    fatal_if(numSets < 2, "TaggedSassAssociative: numSets must be >= 2");
    fatal_if(assoc == 0, "TaggedSassAssociative: assoc must be > 0");
    fatal_if(assoc > 16, "TaggedSassAssociative: assoc must be <= 16");

    index_bits = floorLog2(numSets);
    fatal_if(index_bits + kCoverageT <= 0,
             "TaggedSassAssociative: index_bits + coverage must be > 0");

    initializeKeys();
}

void
TaggedSassAssociative::initializeKeys()
{
    int i;
    unsigned char k1_M[16];

    for (i = 0; i < 16; i++) {
        k0[i] = i;
        w0[i] = ~(16 - i) & 0xf;
    }

    qarma64KeySpecialisation(k0, w0, k1, k1_M, w1);
}

uint64_t
TaggedSassAssociative::hash_first_layer(Addr addr, unsigned way, uint64_t securityDomain) const
{
    int i;
    unsigned char p[16], t[16];

    Addr original_tag_and_set = addr >> setShift;

    for (i = 0; i < 16; i++) {
        p[i] = (original_tag_and_set >> (4 * i)) & 0xf;
        // t[i] = 0;
        t[i] = securityDomain & 0xf;
        securityDomain >>= 4;
    }
    t[0] = way & 0xf;
    // uint64_t sd = securityDomain;
    // for (int j = 1; j < 16; j++) {
    //     t[j] = sd & 0xf;
    //     sd >>= 4;
    // }

    qarma64Encrypt(p, w0, w1, k0, k1, t, kRounds);

    uint64_t h = 0;
    for (i = 0; i < 16; i++) {
        h |= (uint64_t)p[i] << (4 * i);
    }
    return h;
}

uint64_t
TaggedSassAssociative::hash_second_layer(uint64_t scatterindex, unsigned way, uint64_t securityDomain) const
{
    int i;
    unsigned char p[16], t[16];
    // if(securityDomain!=0)
    // printf("securityDomain = %x\n", securityDomain);

    Addr original = ((Addr)(way & 0xFF) << ((sizeof(Addr) - 1) * 8)) |
                    (scatterindex & setMask & securityDomain);

    for (i = 0; i < 16; i++) {
        p[i] = (original >> (4 * i)) & 0xf;
        t[i] = 0;
        // t[i] = securityDomain & 0xf;
        // securityDomain >>= 4;
    }
        
    // uint64_t sd = securityDomain;
    // for (int j = 0; j < 16; j++) {
    //     t[j] = sd & 0xf;
    //     sd >>= 4;
    // }

    qarma64Encrypt(p, w0, w1, k0, k1, t, kRounds);

    uint64_t h = 0;
    for (i = 0; i < 16; i++) {
        h |= (uint64_t)p[i] << (4 * i);
    }
    return h;
}

// uint64_t
// TaggedSassAssociative::hash_second_layer(Addr addr,
//                                          uint64_t scatterindex,
//                                          unsigned way) const
// {
//     int i;
//     unsigned char p[16], t[16];

//     // Mix in address entropy (tag+set bits) + scatter + way.
//     Addr tag_and_set = addr >> setShift;

//     Addr original =
//         tag_and_set ^
//         (tag_and_set >> 17) ^
//         (tag_and_set << 13) ^
//         ((Addr)way << 56) ^
//         ((Addr)scatterindex << 1);

//     for (i = 0; i < 16; i++) {
//         p[i] = (original >> (4 * i)) & 0xf;
//         t[i] = 0;
//     }

//     qarma64Encrypt(p, w0, w1, k0, k1, t, kRounds);

//     uint64_t h = 0;
//     for (i = 0; i < 16; i++) {
//         h |= (uint64_t)p[i] << (4 * i);
//     }
//     return h;
// }

std::vector<ReplaceableEntry*>
TaggedSassAssociative::getPossibleEntries(const KeyType &key) const
{
    std::vector<unsigned> scatterlocations;
    int ways_per_hash = 64/(index_bits + kCoverageT);
    int coverage_set_mask = (1 << (index_bits + kCoverageT)) - 1;
    int way = 0;
    while ( way < assoc ) {
        uint64_t digest = hash_first_layer(key.address, way, key.securityDomain);
        for (int ctr = 0; ctr < ways_per_hash
            && way < assoc; ++ctr, ++way, digest >>= (index_bits + kCoverageT)) {
            // Extract the set index from the digest
            unsigned idx = digest & coverage_set_mask;
            scatterlocations.push_back(idx);
        }
    }

     std::vector<ReplaceableEntry*> locations;
    for(way = 0; way < assoc; way++) {
        
        uint64_t digest = hash_second_layer(scatterlocations.at(way), way, key.securityDomain);

        // Extract the set index from the digest
        unsigned idx = digest & setMask;
    
        locations.push_back(getEntry(idx, way));
    }
    return locations;
}

// uint32_t
// TaggedSassAssociative::extractSetSass(const KeyType &key, unsigned way) const
// {
//     // const int bits = index_bits + kCoverageT;
//     // const uint32_t coverage_mask = (1u << bits) - 1u;

//     // const int ways_per_hash = 64 / bits;
//     // const unsigned group_base = (way / ways_per_hash) * ways_per_hash;
//     // const unsigned group_off  = (way % ways_per_hash);

//     // uint64_t digest1 = hash_first_layer(key.address, group_base);
//     // digest1 >>= (group_off * bits);
//     // uint64_t scatter = digest1 & coverage_mask;

//     // uint64_t digest2 = hash_second_layer(scatter, way);

//     // return (uint32_t)(digest2 & setMask);

//     const int bits = index_bits + kCoverageT;
//     const uint32_t coverage_mask = (1u << bits) - 1u;

//     uint64_t digest1 = hash_first_layer(key.address, way);
//     uint64_t scatter = digest1 & coverage_mask;

//     // 2) Second-layer hash per-way
//     uint64_t digest2 = hash_second_layer(scatter, way);

//     return (uint32_t)(digest2 & setMask);
// }

// std::vector<ReplaceableEntry*>
// TaggedSassAssociative::getPossibleEntries(const KeyType &key) const
// {
//     std::vector<ReplaceableEntry*> entries;
//     entries.reserve(assoc);

//     // std::unordered_set<uint32_t> seen;
//     // int dup = 0;
//     for (unsigned way = 0; way < assoc; ++way) {
//         const uint32_t set = extractSetSass(key, way);
//         // ---- DEBUG: duplicate detection ----
//         // if (!seen.insert(set).second) {
//         //     dup++;
//         // }
//         // -----------------------------------
//         entries.push_back(getEntry(set, way));
//     }

//      // ---- DEBUG: report duplicates ----
//     // if (dup > 0) {
//     //     printf(
//     //             "SASS DUPLICATES addr=%#lx dup=%d assoc=%u\n",
//     //             key.address, dup, assoc);
//     // }
//     // ----------------------------------

//     return entries;
// }

Addr
TaggedSassAssociative::extractTag(const Addr addr) const
{
    // Store "tag + original set bits" (everything above block offset)
    return addr >> setShift;
}

Addr
TaggedSassAssociative::regenerateAddr(const KeyType &key,
                                      const ReplaceableEntry *entry) const
{
    // key.address here is the stored tag (tag+set bits), provided by BaseSetAssoc
    return (key.address << setShift);
}


} // namespace gem5
