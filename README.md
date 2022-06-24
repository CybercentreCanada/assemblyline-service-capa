# CAPA Service

This service is a wrapper around the main functions of flare-capa.

## Submission Parameters & Configuration

### Parameters:

- `renderer`: Multiple output method were added to the module. They may be removed at some point, but at the current time, they offer different level of information. The parameter's default value can be modified by an administrator, and the renderer can be chosen per submission.
    - The "simple" renderer shows a plain list of capability, with no context.
    - The "default" renderer mimics the flare-capa's default output (when not specifying -v or -vv). Three tables will be shown, ATT&CK, MBC and the other Capabilities.
    - The "verbose" renderer. This one is built based on the -vv (very verbose) option of flare-capa, but doesn't show the addresses section, and only shows the namespace, description, ATT&CK and MBC values. Each capability becomes its own foldable resultsection.

### Config (set by administrator):

- `max_file_size`: Since flare-capa is very time-consuming, any file size larger than this parameter will be completely ignored. You may modify this along with the timeout for the module to find your best configuration.
