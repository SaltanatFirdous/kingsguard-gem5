#ifndef __MEM_CACHE_TAGS_INDEXING_POLICIES_TAGGED_SASS_ASSOCIATIVE_HH__
#define __MEM_CACHE_TAGS_INDEXING_POLICIES_TAGGED_SASS_ASSOCIATIVE_HH__

#include <cstdint>
#include <vector>

#include "mem/cache/tags/tagged_entry.hh"   // TaggedIndexingPolicy, KeyType
#include "params/TaggedSassAssociative.hh"

namespace gem5
{

class TaggedSassAssociative : public TaggedIndexingPolicy
{
  protected:
    // QARMA material (hardcoded like old SassAssoc)
    unsigned char k0[16];
    unsigned char k1[16];
    unsigned char w0[16];
    unsigned char w1[16];

    int index_bits;

    static constexpr int kCoverageT = 0; // start safe
    static constexpr int kRounds = 6;

    void initializeKeys();

    uint64_t hash_first_layer(Addr addr, unsigned way) const;
    uint64_t hash_second_layer(uint64_t scatterindex, unsigned way) const;

    uint32_t extractSetSass(const KeyType &key, unsigned way) const;

  public:
    PARAMS(TaggedSassAssociative);

    TaggedSassAssociative(const Params &p);

    std::vector<ReplaceableEntry*> getPossibleEntries(const KeyType &key) const override;

    Addr regenerateAddr(const KeyType &key,
                        const ReplaceableEntry *entry) const override;
    Addr extractTag(const Addr addr) const override;

};

} // namespace gem5

#endif
