# Raccoon
A python (flask) based web app for bug bounty reconnaissance using nuclei tools

## Installation
1. First download and install all the projectdiscovery tool such as nuclei,httpx,subfinder and naabu or download the release file from github and place it in the app folder
2. Now install the required python libraries using ```pip install -r requirements.txt```
3. Now run ```python app.py```

The application run in http://localhost:5000 you can change the port in app.py file
There is an authentication check and default password is ```admin:password``` you can change it app.py file

You can also use the dockerfile and run it using 
### build
```docker build -t recon-framework .```
### run
```docker run -d \
  -p 5000:5000 \
  --name recon \
  recon-framework
```
