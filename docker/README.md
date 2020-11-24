## Docker

### Build

```
docker build -t provable/ptokens-verifier -f docker/verifier.Dockerfile .
```

```
docker build -t provable/ptokens-strongbox-apkdiff -f docker/apkdiff.Dockerfile
```

#### Build Arguments

In order to overwrite the following just add the `--build-arg` option when building the docker.
Use the option `--env` if you want to overwrite them when running the docker.

 - `BRIDGES`: comma separated list of URLs from which we can get the evidence (default `http://localhost:3002/pbtc-on-eth`)
 - `CACHE_PATH`: path to the docker folder where the APK and the proof are supposed to be temporarily stored (default: /home/provable/cache)
 - `SRC_PATH`: path to the docker source code folder (default: /home/provable/apps/strongbox)

### Run 

```
docker run -v cache:/home/provable/cache provable/ptokens-verifier <app_path> <proof_path>
```

#### Useful settings:

When using docker run, you set the following environment variables for more verbose logging (disabled by default):

 - DEBUG=1
 - INFO=1

### Test

If you are running the bridge locally or the IPFS gateway locally, specify the `--nework host` flag
when running the container.