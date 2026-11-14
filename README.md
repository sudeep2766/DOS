Server files are ready on the ubuntu server.

Was made with python:

First created a rest api with py, then the seed.py
2->Created a db with mariadb -- social.

dos file is just a js file that generates traffic -> test.js

Run the js by:

```bash
k6 run test.js (also specify the ip addr)
```

installation of k6 on arch:
```bash
yay -S k6-bin
```

installation on debian:
```bash
sudo mkdir -p /usr/share/keyrings
curl -fsSL https://dl.k6.io/key.gpg | sudo gpg --dearmor -o /usr/share/keyrings/k6-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update
sudo apt-get install k6
```

installation on mac:
```bash
brew install k6
```

fk windows
