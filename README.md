# Dokumentum Hitelesítő Rendszer Hyperledger Fabric alapokon

Ez a projekt egy blokklánc-alapú dokumentumhitelesítő rendszer, amely a Hyperledger Fabric technológiára épül.

A rendszer nem magukat a dokumentumokat tárolja a blokkláncon, hanem azok kriptográfiai lenyomatát (hash). Ennek köszönhetően a megoldás hatékony, skálázható, és megfelel a modern adatvédelmi elvárásoknak is.


## Tartalomjegyzék

* [Funkciók](#funkciók)
* [Architektúra](#architektúra)
* [Előfeltételek](#előfeltételek)
* [Telepítés](#telepítés)
* [Használat](#használat)
* [Admin funkciók](#admin-funkciók)
* [Projekt struktúra](#projekt-struktúra)



## Funkciók

A rendszer célja, hogy egy teljes körű dokumentumkezelési és hitelesítési folyamatot biztosítson:

* Dokumentumok biztonságos regisztrálása egyedi hash alapján
* Dokumentumok hitelességének ellenőrzése fájl vagy hash segítségével
* Verziókezelés és teljes életút (timeline) követése
* Adminisztrációs felület felhasználók kezelésére
* Dokumentum státuszok kezelése (`REGISTERED`, `REVOKED`, `ARCHIVED`)
* Audit napló export CSV formátumban
* Duplikált dokumentumok kiszűrése hash összehasonlítással


## Architektúra

A rendszer három jól elkülöníthető rétegből épül fel:

### 1. Frontend – FastAPI (Python)

A felhasználói felület FastAPI segítségével készült.
Feladata a felhasználói interakciók kezelése, valamint a Gateway API-val való kommunikáció.

### 2. Gateway API – Node.js (Express)

Ez a komponens biztosítja a kapcsolatot a frontend és a blokklánc között.
Feladatai közé tartozik:

* JWT alapú hitelesítés kezelése
* Felhasználók tárolása (SQLite)
* Identitások kezelése a Fabric CA segítségével
* Chaincode hívások közvetítése

### 3. Chaincode – Hyperledger Fabric

A rendszer üzleti logikája a blokkláncon fut.
A `DocumentContract` felelős:

* dokumentumok kezeléséért
* verziók tárolásáért
* hash-ek ellenőrzéséért
* állapotok kezeléséért


## Előfeltételek

A rendszer futtatásához az alábbiak szükségesek:

* Docker és Docker Compose
* Node.js 
* Python 3.8 vagy újabb
* Git
* Alapvető Hyperledger Fabric ismeretek


## Telepítés

### 1. Repository klónozása

```bash
git clone <repository_url>
cd blokk
```



### 2. Hyperledger Fabric hálózat indítása

```bash
./network.sh up
./network.sh createChannel -c mychannel
./network.sh deployCC -ccn document-contract -ccp ../../chaincode/document-contract/ -ccl javascript
```

Győződj meg róla, hogy az alábbi fájlok elérhetők:

* `connection-org1.json`
* `tls/ca.crt`


### 3. Környezeti változók beállítása

#### frontend `.env`

```env
NODE_GATEWAY_URL=http://localhost:3000
JWT_SECRET=super_secret_change_this
DEBUG_AUTH=0
```

#### gateway `.env`

```env
PORT=3000
CHANNEL=mychannel
CHAINCODE=document-contract
PEER_NAME=peer0.org1.example.com
MSP_ID=Org1MSP
CCP_PATH=./fabric/connection-org1.json
PEER_TLS_CA_PATH=./fabric/tls/ca.crt
USERS_ROOT=./fabric/users
CA_ADMIN=admin
CA_ADMIN_PW=adminpw
JWT_SECRET=super_secret_change_this
JWT_EXPIRES_IN=8h
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin
USERS_DB_PATH=./data/users.sqlite
```

Fontos: mindenképp változtasd meg a `JWT_SECRET` és `ADMIN_PASSWORD` értékeket!



### 4. Függőségek telepítése

#### Gateway

```bash
cd gateway-api-node
npm install
```

#### Frontend

```bash
cd ../fronted-app-python
pip install -r requirements.txt
```


## Használat

### 1. Gateway indítása

```bash
npm start
```

### 2. Frontend indítása

```bash
uvicorn app:app --reload --port 8000
```


### 3. Alkalmazás megnyitása

Nyisd meg a böngészőben:

```
http://localhost:8000
```

#### Alap funkciók:

* Bejelentkezés (admin / admin)
* Dokumentum feltöltés és regisztráció
* Dokumentum ellenőrzés hash vagy fájl alapján
* Verziók és előzmények megtekintése


## Admin funkciók

Admin jogosultsággal a következő funkciók érhetők el:

* `/admin/users` → felhasználók kezelése
* `/admin/network` → blokklánc és gateway állapotának monitorozása

## Projekt struktúra

```
. blokk/
├── chaincode/
│   └── document-contract/
├── fronted-app-python/
│   ├── app.py
│   ├── requirements.txt
│   ├── static/
│   └── templates/
├── gateway-api-node/
│   ├── app.js
|   |── fabric/
|   |    ├── tls/ca.crt
|   |    |── users/
│   |    └── connection-org1.json
│   ├── package.json
│   └── data/users.sqlite
└── README.md
```

A projekt nem tartalmazza a hálózatspecifikus konfigurációs fájlokat, mint például a ca.crt és a connection-org1.json. Ezeket a fájlokat a saját Hyperledger Fabric hálózatból kell előállítani vagy kinyerni, és a megfelelő helyre elhelyezni a futtatáshoz.


