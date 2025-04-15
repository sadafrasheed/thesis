ARG CODE_ROOT

# Use a lightweight Python image
FROM python:3.12-slim

# Set the working directory
WORKDIR /app


RUN apt update && apt install -y \
    python3 python3-pip python3-venv python3-setuptools python3-dev \
    build-essential m4 automake libtool flex bison libgmp-dev libssl-dev wget git


COPY ../code/lib/ /app/lib/
COPY ../code/client/ /app/client/
COPY ../code/requirements.txt /app/requirements.txt

# Copy the entrypoint script
RUN chmod +x /app/client/entrypoint.sh


RUN mkdir /installs

RUN cd /installs && \
    pip install setuptools && \
    wget http://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz && \
    tar xf pbc-0.5.14.tar.gz && \
    cd pbc-0.5.14/ && \
    ./configure && make && make install && ldconfig 

RUN cd /installs && \
    git clone https://github.com/JHUISI/charm.git && \
    cd charm/ && \
    ./configure.sh && make && make install && ldconfig 


# RUN cd /app && \
#     python3 -m venv venv  --system-site-packages && \
#     . venv/bin/activate

RUN pip install --upgrade pip && \
    pip install -r requirements.txt


RUN mkdir /app/jsons

# Set the entrypoint script
ENTRYPOINT ["/app/client/entrypoint.sh"]
#CMD tail -f /dev/null 