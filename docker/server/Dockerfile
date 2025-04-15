ARG CODE_ROOT

# Use the latest Ubuntu image
FROM ubuntu:22.04

# Set the working directory inside the container
WORKDIR /app

# Update and install necessary packages
RUN apt update && apt install -y \
    python3 python3-pip python3-venv python3-setuptools python3-dev \
    sqlite3  \
    net-tools iputils-ping curl nano wget git \
    build-essential m4 automake libtool flex bison libgmp-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy server scripts (if you have any Python scripts for WebSockets, API, etc.)
COPY ../code/server /app/server
COPY ../code/lib /app/lib
COPY ../code/requirements.txt /app/requirements.txt

RUN mkdir /installs

RUN cd /installs && \
    wget http://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz && \
    tar xf pbc-0.5.14.tar.gz && \
    cd pbc-0.5.14/ && \
    ./configure && make && make install && ldconfig 

RUN cd /installs && \
    git clone https://github.com/JHUISI/charm.git && \
    cd charm/ && \
    ./configure.sh && make && make install


# RUN cd /app && \
#     python3 -m venv venv  --system-site-packages && \
#     . venv/bin/activate

RUN pip install --upgrade pip && \
    pip install -r requirements.txt
    

RUN mkdir /app/jsons

RUN export SERVER_ID="ubuntu-cloud-server" &&  \
    cd /app && \
    python3 -m lib.db init

# Copy the entrypoint script
RUN chmod +x /app/server/entrypoint.sh


# Expose the necessary ports
# Web server
EXPOSE 65432  



# Run the Python server
ENTRYPOINT ["/app/server/entrypoint.sh"]
#CMD python3 -m server/listen
#CMD tail -f /dev/null 