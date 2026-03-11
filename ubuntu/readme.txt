1 - Install pcsc-lite

sudo apt-get install  pcscd
sudo apt-get install  pcsc-tools
sudo apt-get install  libpcsclite1
sudo apt-get install  libpcsclite-dev
sudo apt-get install  libccid
sudo apt-get install  libusb-dev


2- Install OPENSSL libraires

sudo apt-get install libssl-dev

3- Compile TLSSE
./make.sh

4- Tests Local
./server.sh start a local TLSPSK server
./local.sh TLSSE client establish a session with local server

5-  Tests on-line
./hello.sh
./auth.sh
./console.sh
./remotese.sh


