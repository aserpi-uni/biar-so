Electronic bulletin board
=========================

### Requirements
Realizzazione di un servizio "bacheca elettronica" il quale
permetta ad ogni utente autorizzato di inviare messaggi che
possono essere letti da ogni altro utente interessato a consultare
la bacheca stessa.  
Il servizio di accesso alla bacheca elettronica deve essere offerto da
un server che accetta e processa sequenzialmente o in concorrenza (a scelta)
le richieste dei client (residenti, in generale, su macchine diverse dal server).  
Un client deve fornire ad un utente le seguenti funzioni:
1. Leggere tutti i messaggi presenti sulla bacheca elettronica.
2. Spedire un nuovo messaggio sulla bacheca elettronica.
3. Rimuovere un messaggio dalla bacheca elettronica, se inserito
   dallo stesso utente interessato a cancellarlo (verifica da effettuare
   tramite un meccanismo di autenticazione a scelta).
Un messaggio deve contenere almeno i campi Mittente, Oggetto e Testo.  
Si precisa che la specifica richiede la realizzazione del software sia per
l'applicazione client che per l'applicazione server.

### Procedures
It is possible to execute the following operations:
* register a new user
* insert a new message
* read a message
* delete and restore the content of a message (only by the proprietary user)
* retrieve the messages inserted by a specific user (from the first page)
* retrieve all messages (from either the first or the last page).

### Board
Users are memorized in an array of size `unities*unit_size` whose dimension is
increased linearly when full.  
Messages are memorized in pages. Each page is memorized in an array of size
`page_size*sizeof(msg)`, pointers to the pages are memorized in an array of size
`pages*sizeof(msg*)` whose dimension is increased by 1.5x when full.

### Server
The server is single thread and works sequentially, i.e. it is able to process only one
request at a time.

### Encryption
TLS 1.2 via [OpenSSL](https://www.openssl.org).
The default algorithm is RSA and the certificate is self-signed, expiring in 23/12/2017
at 21:16:06 GMT.

### Compile and install
This project uses [CMake](https://www.cmake.org), refer to the official website
for what it is and how to use it. Client and server may be compiled independently, but
pay attention to set the same port.  
There are some macros that can be redefined:
* ADDRESS: sets the server address in the client, default "127.0.0.1"
* PAGE_SIZE: messages per page, default 10
* PAGES: preallocated pages, default 5
* PORT: the port number, default 42318
* USERS: users per unit, default 50.
