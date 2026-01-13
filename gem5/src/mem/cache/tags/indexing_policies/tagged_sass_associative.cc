#include "mem/cache/tags/indexing_policies/tagged_sass_associative.hh"

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
TaggedSassAssociative::hash_first_layer(Addr addr, unsigned way) const
{
    int i;
    unsigned char p[16], t[16];

    Addr original_tag_and_set = addr >> setShift;

    for (i = 0; i < 16; i++) {
        p[i] = (original_tag_and_set >> (4 * i)) & 0xf;
        t[i] = 0;
    }
    t[0] = way & 0xf;

    qarma64Encrypt(p, w0, w1, k0, k1, t, kRounds);

    uint64_t h = 0;
    for (i = 0; i < 16; i++) {
        h |= (uint64_t)p[i] << (4 * i);
    }
    return h;
}

uint64_t
TaggedSassAssociative::hash_second_layer(uint64_t scatterindex, unsigned way) const
{
    int i;
    unsigned char p[16], t[16];

    Addr original = ((Addr)(way & 0xFF) << ((sizeof(Addr) - 1) * 8)) |
                    (scatterindex & setMask);

    for (i = 0; i < 16; i++) {
        p[i] = (original >> (4 * i)) & 0xf;
        t[i] = 0;
    }

    qarma64Encrypt(p, w0, w1, k0, k1, t, kRounds);

    uint64_t h = 0;
    for (i = 0; i < 16; i++) {
        h |= (uint64_t)p[i] << (4 * i);
    }
    return h;
}

uint32_t
TaggedSassAssociative::extractSetSass(const KeyType &key, unsigned way) const
{
    const int bits = index_bits + kCoverageT;
    const uint32_t coverage_mask = (1u << bits) - 1u;

    const int ways_per_hash = 64 / bits;
    const unsigned group_base = (way / ways_per_hash) * ways_per_hash;
    const unsigned group_off  = (way % ways_per_hash);

    uint64_t digest1 = hash_first_layer(key.address, group_base);
    digest1 >>= (group_off * bits);
    uint64_t scatter = digest1 & coverage_mask;

    uint64_t digest2 = hash_second_layer(scatter, way);

    return (uint32_t)(digest2 & setMask);
}

std::vector<ReplaceableEntry*>
TaggedSassAssociative::getPossibleEntries(const KeyType &key) const
{
    std::vector<ReplaceableEntry*> entries;
    entries.reserve(assoc);

    for (unsigned way = 0; way < assoc; ++way) {
        const uint32_t set = extractSetSass(key, way);
        entries.push_back(getEntry(set, way));
    }

    return entries;
}

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
