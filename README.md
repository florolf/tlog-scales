# tlog-scales

**Note**: Very much WIP, expect churn and breakage.

This is a library that extracts various [tlog-tiles](https://github.com/C2SP/C2SP/blob/main/tlog-tiles.md) related functionality from [sigmon](https://github.com/florolf/sigmon) and [cross-examination](https://github.com/florolf/cross-examination) for reusability.

Component status:
 - Log reading and proof construction is mostly usable now.
 - Log writing works but is not crash safe yet. There also is no mechanism for collecting cosignatures as of yet.
