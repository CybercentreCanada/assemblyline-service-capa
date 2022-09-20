# CAPA Service

This service is a wrapper around the main functions of mandiant/capa.

## Submission Parameters & Configuration

### Parameters:

- `renderer`: Multiple output method were added to the module. They may be removed at some point, but at the current time, they offer different level of information. The parameter's default value can be modified by an administrator, and the renderer can be chosen per submission.
    - The "simple" renderer shows a plain list of capability, with no context.
    - The "default" renderer mimics capa's default output (when not specifying -v or -vv). Three tables will be shown, ATT&CK, MBC and the other Capabilities.
    - The "verbose" renderer. This one is built based on the -vv (very verbose) option of capa, but doesn't show the addresses section, and only shows the namespace, description, ATT&CK and MBC values. Each capability becomes its own foldable resultsection.

### Config (set by administrator):

- `max_file_size`: Ignore any file larger than this size (default:500KB). Since capa is very time-consuming, any file size larger than this parameter will be completely ignored and the module is going to return early without any results. The module will therefore show up in the "Empty Results" section of the UI.

### Important service-level configuration:

- `timeout`: How much time we let the module run before timing out (default:5 minutes)
- `docker_config.ram_mb`: How much RAM the module can use (default:4GB)
