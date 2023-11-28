## [1.0.0-rc.1](https://github.com/sunflower-ing/core/compare/...v1.0.0-rc.1) (2023-11-28)


### :scissors:Refactor

* add docs to helm chart ([6788b37](https://github.com/sunflower-ing/core/commit/6788b3751550a85d3c424ec8f7878dbe2733a979))
* pass precommits ([a29508a](https://github.com/sunflower-ing/core/commit/a29508acba2173b4102882eb281127425c0345fc))


### 📔 Docs

* add autogenerate docs ([d185e2c](https://github.com/sunflower-ing/core/commit/d185e2c0c096d4647cfcdd9bf46b3e61ee9b2dd7))
* fix github url ([0e3751f](https://github.com/sunflower-ing/core/commit/0e3751f65641c6e8f4978ab6a4a6d7175bc82487))
* fix refactor image to 💈 ([af706c1](https://github.com/sunflower-ing/core/commit/af706c1cbcbca80766ee28e2d3d21a4ceb7500be))
* seve under subpath ([eb4f559](https://github.com/sunflower-ing/core/commit/eb4f55957d4f6b6865ab24fe301096f1e7a3572d))


### 🚀 Features

* add docs image ([f406db0](https://github.com/sunflower-ing/core/commit/f406db05e6b0d984f0f8e98194c2e01db06875ff))
* Add unique_together for Source model to avoid sources duplication ([8625978](https://github.com/sunflower-ing/core/commit/86259780380c194c7ab8a2db897083d115464303))
* **API:** Add REST API endpoints and remove templates ([5e2d64f](https://github.com/sunflower-ing/core/commit/5e2d64f873cb20cc564efe293e847fc1858428f9))
* **api/me:** Add current logged user data view ([439da6d](https://github.com/sunflower-ing/core/commit/439da6de2f5f5278d2e98e983b56440396c02f69))
* **auth:** Add token based auth + OCSP fixes ([7d6c88a](https://github.com/sunflower-ing/core/commit/7d6c88a859103d5a087bae7b7313d0f75869e074))
* **crypto:** Add CRL distribution point and OCSP authority information access ([e2e5eee](https://github.com/sunflower-ing/core/commit/e2e5eeea8fe543c8e2befcc4afb80780e99b66f7))
* **crypto:** Rework some crypto methods and corresponding models ([6bd33a9](https://github.com/sunflower-ing/core/commit/6bd33a9d33af0dfdb9e942a2585684da4df0500c))
* **export:** Export key/cert methods. Some crypto/utils additions like key/cert der encoding. Added some usable methods to Certificate model ([7728735](https://github.com/sunflower-ing/core/commit/77287357334517fee32c3ae99b42ccc5c3590399))
* **export:** Export key/cert methods. Some crypto/utils additions like key/cert der encoding. Added some usable methods to Certificate model ([3dde509](https://github.com/sunflower-ing/core/commit/3dde5096541f69956fdf359146c6dd9d4260c946))
* **filtering:** Add filter functionality for Key,CSR and Certificate list methods ([c37714b](https://github.com/sunflower-ing/core/commit/c37714bbb39c6dafa1b0380e75b04be662de676f))
* **filtering:** Add filter functionality for Key,CSR and Certificate list methods ([e536ada](https://github.com/sunflower-ing/core/commit/e536adadcb4ef2705f4e3092ffc8ffee5b72fa32))
* **helm:** add liveness and readiness probe ([a0bb428](https://github.com/sunflower-ing/core/commit/a0bb42822d1dc341e6b592774a2ecb23de399aa6))
* **import:** Import certificate functionality ([2c4337c](https://github.com/sunflower-ing/core/commit/2c4337c3e6e1b7dfd07ad5acb114e088c2e6bdb1))
* **logging:** Add endpoints to retrieve logs ([6b7511a](https://github.com/sunflower-ing/core/commit/6b7511a0304c4d269b3b8c33dfa190b404ef4355))
* **logging:** Add logging ([d26549e](https://github.com/sunflower-ing/core/commit/d26549ef21806058b5d89e7dac1627652e480efa))
* **OCSP:** OCSP endpoint and much more shit ([424a801](https://github.com/sunflower-ing/core/commit/424a8015911796df01d8f78e0fede46f7b27690e))
* **pagination:** Add pagination ([2de7632](https://github.com/sunflower-ing/core/commit/2de76323924dc78823d04b795b36bf3d2abcfc1b))
* **revocation:** Add CRL model and revocation possibility ([e85da09](https://github.com/sunflower-ing/core/commit/e85da09192134b6de35f9f94829c98bc7466b293))
* **revocation:** Add slug to CSR and update revocation code ([d4b9547](https://github.com/sunflower-ing/core/commit/d4b9547511c60a5eb49650a42c627520b7b5508f))
* **search:** Add search by name field functionality for list endpoints ([370e436](https://github.com/sunflower-ing/core/commit/370e43629bf25539bfd57adbe91c12b2ad56a376))
* **search:** Add search by name field functionality for list endpoints ([12380f1](https://github.com/sunflower-ing/core/commit/12380f1e6289bc488213716456aa767768963f91))
* **swagger/redoc:** Add schema generation and swagger/redoc views ([33c579e](https://github.com/sunflower-ing/core/commit/33c579ec6e1cd9cb912b27eea5db7bae56fdcad4))
* **swagger/redoc:** Add schema generation and swagger/redoc views ([6fc445a](https://github.com/sunflower-ing/core/commit/6fc445a0f7d5bf095a5cf59a51ac1e7957ae044e))
* **system/groups:** Add endpoints for groups and permissions management ([620c27f](https://github.com/sunflower-ing/core/commit/620c27f5bd648fd25bd471597896be300d359be4))
* **system/users:** Add endpoint for system users management ([3be751c](https://github.com/sunflower-ing/core/commit/3be751c5b9983325acbcfc38fe18d1342e3fee00))


### 🛠 Fixes

* Add corresponding migration ([a50d92c](https://github.com/sunflower-ing/core/commit/a50d92c77631965adc2e710314cf315030f67f1a))
* add dockerignore ([d0c9882](https://github.com/sunflower-ing/core/commit/d0c988227c5cba9356c9ee9808252669bfc4c38a))
* add external values ([a6a8d76](https://github.com/sunflower-ing/core/commit/a6a8d763847e31fa3f82532bde78a744b7062363))
* Add migration ([d2b8a54](https://github.com/sunflower-ing/core/commit/d2b8a547f14f1f1c0af8099cf9317ecc64ad9855))
* context for docs ([9e642a6](https://github.com/sunflower-ing/core/commit/9e642a6337fc4e849a104be7ccc58fbb291131bd))
* crsf_trsuted_domains ([be19d79](https://github.com/sunflower-ing/core/commit/be19d79d3a73a6d48c261cda19dea9dd65c55984))
* CSRF start from https ([c8e3bf8](https://github.com/sunflower-ing/core/commit/c8e3bf89dc9047ef8f8eb7c8bf537d8db46d06d0))
* docs under /docs ([156c471](https://github.com/sunflower-ing/core/commit/156c47148c6a45b6e275bef8d69dc785a03b58c1))
* env for debug hosts and csrf ([99967cb](https://github.com/sunflower-ing/core/commit/99967cbb08ff2d57a4b318b61cd944dee69b4665))
* image name for application ([3538243](https://github.com/sunflower-ing/core/commit/35382436cabda02e3694e00bdd41cf3d762ff420))
* images from werf ([262e0d8](https://github.com/sunflower-ing/core/commit/262e0d8df6c766a616fcac0d104774346e8d70d6))
* lables for application in werf ingress ([0a20309](https://github.com/sunflower-ing/core/commit/0a20309e03be0a25f99d58727a76a5e49d06737c))
* makefile add kube-login ([5cde10d](https://github.com/sunflower-ing/core/commit/5cde10d60cda5470eae3b8db3ad27a751be17a7f))
* migrations to correct pg host and True to debug ([8552d8a](https://github.com/sunflower-ing/core/commit/8552d8a768ce48f9bbe1ecdcbc3f4c1dd279e1db))
* names for ingress ([a27b76d](https://github.com/sunflower-ing/core/commit/a27b76dd8ec6750db9da79e198845fb02f66811a))
* new dockerfile for pull images ([5e79f0d](https://github.com/sunflower-ing/core/commit/5e79f0d63db8a09c8d18b24eee9b89952a826653))
* remove md from dockerignore ([626a212](https://github.com/sunflower-ing/core/commit/626a21218843078d274e8cced6d68636ebdfa222))
* sa and registry secret ([fe3f7b3](https://github.com/sunflower-ing/core/commit/fe3f7b343f217a0ae401d09784d0d1e82bad8a41))
* Update CSR serializer for KU & EKU ([9d63de7](https://github.com/sunflower-ing/core/commit/9d63de7d1202ac785daea050117e57e0d13b3d57))
* werf only ingress ([b996b9b](https://github.com/sunflower-ing/core/commit/b996b9b15eefb3e18d26a5322497ae2d7f3b7777))
* **#17:** Fix 400 on group creation ([ce4b6d9](https://github.com/sunflower-ing/core/commit/ce4b6d92063f87176b4cfcd8db76b5bd14e754c1))
* **#18:** Fix duplicates on OCSP source creation ([9d91468](https://github.com/sunflower-ing/core/commit/9d9146840c7a14bce9d404349cb315c4a9315ff0))
* **migrations:** add migrations job ([8b72a3d](https://github.com/sunflower-ing/core/commit/8b72a3d294604209905a6a4f2623e4ecf98ff9b4))
* **teleport:** move stage to teleport ([214a48b](https://github.com/sunflower-ing/core/commit/214a48bbd15d09612db37d68ea4186f518293f6c))

### [1.0.1-rc.1](https://github.com/AmazeIT/sunflower/compare/v1.0.0...v1.0.1-rc.1) (2023-07-02)


### 💈  Refactor

* add docs to helm chart ([6788b37](https://github.com/AmazeIT/sunflower/commit/6788b3751550a85d3c424ec8f7878dbe2733a979))


### 📔 Docs

* add autogenerate docs ([d185e2c](https://github.com/AmazeIT/sunflower/commit/d185e2c0c096d4647cfcdd9bf46b3e61ee9b2dd7))
* fix github url ([0e3751f](https://github.com/AmazeIT/sunflower/commit/0e3751f65641c6e8f4978ab6a4a6d7175bc82487))
* seve under subpath ([eb4f559](https://github.com/AmazeIT/sunflower/commit/eb4f55957d4f6b6865ab24fe301096f1e7a3572d))


### 🚀 Features

* add docs image ([f406db0](https://github.com/AmazeIT/sunflower/commit/f406db05e6b0d984f0f8e98194c2e01db06875ff))
* **crypto:** Add CRL distribution point and OCSP authority information access ([e2e5eee](https://github.com/AmazeIT/sunflower/commit/e2e5eeea8fe543c8e2befcc4afb80780e99b66f7))
* **revocation:** Add CRL model and revocation possibility ([e85da09](https://github.com/AmazeIT/sunflower/commit/e85da09192134b6de35f9f94829c98bc7466b293))


### 🛠 Fixes

* image name for application ([3538243](https://github.com/AmazeIT/sunflower/commit/35382436cabda02e3694e00bdd41cf3d762ff420))
* images from werf ([262e0d8](https://github.com/AmazeIT/sunflower/commit/262e0d8df6c766a616fcac0d104774346e8d70d6))
* lables for application in werf ingress ([0a20309](https://github.com/AmazeIT/sunflower/commit/0a20309e03be0a25f99d58727a76a5e49d06737c))
* names for ingress ([a27b76d](https://github.com/AmazeIT/sunflower/commit/a27b76dd8ec6750db9da79e198845fb02f66811a))
* new dockerfile for pull images ([5e79f0d](https://github.com/AmazeIT/sunflower/commit/5e79f0d63db8a09c8d18b24eee9b89952a826653))
* sa and registry secret ([fe3f7b3](https://github.com/AmazeIT/sunflower/commit/fe3f7b343f217a0ae401d09784d0d1e82bad8a41))
* werf only ingress ([b996b9b](https://github.com/AmazeIT/sunflower/commit/b996b9b15eefb3e18d26a5322497ae2d7f3b7777))
* **migrations:** add migrations job ([8b72a3d](https://github.com/AmazeIT/sunflower/commit/8b72a3d294604209905a6a4f2623e4ecf98ff9b4))
* **teleport:** move stage to teleport ([214a48b](https://github.com/AmazeIT/sunflower/commit/214a48bbd15d09612db37d68ea4186f518293f6c))

## [1.0.0](https://github.com/AmazeIT/sunflower/compare/...v1.0.0) (2023-05-01)


### 💈  Refactor

* pass precommits ([a29508a](https://github.com/AmazeIT/sunflower/commit/a29508acba2173b4102882eb281127425c0345fc))


### 🚀 Features

* **helm:** add liveness and readiness probe ([a0bb428](https://github.com/AmazeIT/sunflower/commit/a0bb42822d1dc341e6b592774a2ecb23de399aa6))


### 🛠 Fixes

* add dockerignore ([d0c9882](https://github.com/AmazeIT/sunflower/commit/d0c988227c5cba9356c9ee9808252669bfc4c38a))
* crsf_trsuted_domains ([be19d79](https://github.com/AmazeIT/sunflower/commit/be19d79d3a73a6d48c261cda19dea9dd65c55984))
* CSRF start from https ([c8e3bf8](https://github.com/AmazeIT/sunflower/commit/c8e3bf89dc9047ef8f8eb7c8bf537d8db46d06d0))
* env for debug hosts and csrf ([99967cb](https://github.com/AmazeIT/sunflower/commit/99967cbb08ff2d57a4b318b61cd944dee69b4665))
* makefile add kube-login ([5cde10d](https://github.com/AmazeIT/sunflower/commit/5cde10d60cda5470eae3b8db3ad27a751be17a7f))
* migrations to correct pg host and True to debug ([8552d8a](https://github.com/AmazeIT/sunflower/commit/8552d8a768ce48f9bbe1ecdcbc3f4c1dd279e1db))

## [1.0.0-rc.2](https://github.com/AmazeIT/sunflower/compare/v1.0.0-rc.1...v1.0.0-rc.2) (2023-04-26)

## [1.0.0-rc.1](https://github.com/AmazeIT/sunflower/compare/...v1.0.0-rc.1) (2023-04-26)


### 💈  Refactor

* pass precommits ([a29508a](https://github.com/AmazeIT/sunflower/commit/a29508acba2173b4102882eb281127425c0345fc))


### 🛠 Fixes

* add dockerignore ([d0c9882](https://github.com/AmazeIT/sunflower/commit/d0c988227c5cba9356c9ee9808252669bfc4c38a))
* migrations to correct pg host and True to debug ([8552d8a](https://github.com/AmazeIT/sunflower/commit/8552d8a768ce48f9bbe1ecdcbc3f4c1dd279e1db))
