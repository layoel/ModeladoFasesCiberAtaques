FROM ubuntu:18.04 as base

#comentarios
#descargarlo
RUN apt-get update && apt-get install -y wget && apt-get -y install sudo && apt-get install -y automake libpcap-dev libtool make && rm -rf /var/lib/apt/lists/* 

RUN adduser --disabled-password --gecos '' docker
RUN adduser docker sudo
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

#USER docker

# this is where I was running into problems with the other approaches
#RUN sudo apt-get update

RUN wget https://tranalyzer.com/download/tranalyzer/tranalyzer2-0.8.7lmw1.tar.gz 
	#descomprimirlo
RUN tar xzf tranalyzer2-0.8.7lmw1.tar.gz 
	#instalarlo
ENTRYPOINT ["setup.sh"]
RUN cd tranalyzer2-0.8.7
#Save this location in the variable $T2HOME:
RUN T2HOME="$PWD"
RUN echo $T2HOME /home/user/tranalyzer2-0.8.7/


#PARA CREAR EL CONTENEDOR HACEMOS DOCKER BUILD -t tranalyzer .
