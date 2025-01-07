[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg?sanitize=true)](https://discord.gg/GUAy9wErNu)
[![](https://img.shields.io/discord/908084610158714900)](https://discord.gg/GUAy9wErNu)
[![Static Badge](https://img.shields.io/badge/github-assemblyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline)
[![Static Badge](https://img.shields.io/badge/github-assemblyline\_service\_capa-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline-service-capa)
[![GitHub Issues or Pull Requests by label](https://img.shields.io/github/issues/CybercentreCanada/assemblyline/service-capa)](https://github.com/CybercentreCanada/assemblyline/issues?q=is:issue+is:open+label:service-capa)
[![License](https://img.shields.io/github/license/CybercentreCanada/assemblyline-service-capa)](./LICENSE)
# CAPA Service

This service uses the CAPA open source library to identify what the program at hand could do.

## Service Details

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

## Image variants and tags

Assemblyline services are built from the [Assemblyline service base image](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
which is based on Debian 11 with Python 3.11.

Assemblyline services use the following tag definitions:

| **Tag Type** | **Description**                                                                                  |      **Example Tag**       |
| :----------: | :----------------------------------------------------------------------------------------------- | :------------------------: |
|    latest    | The most recent build (can be unstable).                                                         |          `latest`          |
|  build_type  | The type of build used. `dev` is the latest unstable build. `stable` is the latest stable build. |     `stable` or `dev`      |
|    series    | Complete build details, including version and build type: `version.buildType`.                   | `4.5.stable`, `4.5.1.dev3` |

## Running this service

This is an Assemblyline service. It is designed to run as part of the Assemblyline framework.

If you would like to test this service locally, you can run the Docker image directly from the a shell:

    docker run \
        --name Capa \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-capa

To add this service to your Assemblyline deployment, follow this
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

General Assemblyline documentation can be found at: https://cybercentrecanada.github.io/assemblyline4_docs/

# Service CAPA

Ce service utilise la bibliothèque open source CAPA pour identifier ce que le programme en question peut faire.

## Service Details

### Paramètres :

- `renderer` : Plusieurs méthodes de sortie ont été ajoutées au module. Il est possible qu'elles soient supprimées à un moment donné, mais pour l'instant, elles offrent différents niveaux d'information. La valeur par défaut du paramètre peut être modifiée par un administrateur, et le rendu peut être choisi par soumission.
    - Le moteur de rendu « simple » affiche une simple liste de capacités, sans contexte.
    - Le rendu « default » imite la sortie par défaut de capa (lorsque -v ou -vv n'est pas spécifié). Trois tableaux seront affichés, ATT&CK, MBC et les autres capacités.
    - Le moteur de rendu « verbeux ». Celui-ci est basé sur l'option -vv (très verbeux) de capa, mais n'affiche pas la section des adresses, et ne montre que l'espace de noms, la description, les valeurs ATT&CK et MBC. Chaque capacité devient sa propre section de résultats pliable.

### Config (défini par l'administrateur) :

- `max_file_size` : Ignore tout fichier dont la taille est supérieure à cette valeur (par défaut : 500 Ko). Puisque capa prend beaucoup de temps, tout fichier plus grand que ce paramètre sera complètement ignoré et le module retournera prématurément sans aucun résultat. Le module apparaîtra donc dans la section « Résultats vides » de l'interface utilisateur.

### Configuration importante au niveau du service :

- `timeout` : Combien de temps nous laissons le module s'exécuter avant qu'il ne s'arrête (par défaut : 5 minutes).
- `docker_config.ram_mb` : Combien de RAM le module peut utiliser (par défaut : 4GB)

## Variantes et étiquettes d'image

Les services d'Assemblyline sont construits à partir de l'image de base [Assemblyline service](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
qui est basée sur Debian 11 avec Python 3.11.

Les services d'Assemblyline utilisent les définitions d'étiquettes suivantes:

| **Type d'étiquette** | **Description**                                                                                                |  **Exemple d'étiquette**   |
| :------------------: | :------------------------------------------------------------------------------------------------------------- | :------------------------: |
|   dernière version   | La version la plus récente (peut être instable).                                                               |          `latest`          |
|      build_type      | Type de construction utilisé. `dev` est la dernière version instable. `stable` est la dernière version stable. |     `stable` ou `dev`      |
|        série         | Détails de construction complets, comprenant la version et le type de build: `version.buildType`.              | `4.5.stable`, `4.5.1.dev3` |

## Exécution de ce service

Ce service est spécialement optimisé pour fonctionner dans le cadre d'un déploiement d'Assemblyline.

Si vous souhaitez tester ce service localement, vous pouvez exécuter l'image Docker directement à partir d'un terminal:

    docker run \
        --name Capa \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-capa

Pour ajouter ce service à votre déploiement d'Assemblyline, suivez ceci
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/fr/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

La documentation générale sur Assemblyline peut être consultée à l'adresse suivante: https://cybercentrecanada.github.io/assemblyline4_docs/
