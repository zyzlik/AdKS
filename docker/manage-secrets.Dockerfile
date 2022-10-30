FROM golang
ENV KUBECONFIG=/AdKS/k8s/config

RUN apt update && apt install build-essential curl time -y --no-install-recommends
# Install kubectl
RUN curl -LO "https://dl.k8s.io/release/v1.23.13/bin/linux/amd64/kubectl" 
RUN install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
RUN kubectl version --client
RUN curl -o aws-iam-authenticator https://amazon-eks.s3-us-west-2.amazonaws.com/1.21.2/2021-07-05/bin/linux/amd64/aws-iam-authenticator
RUN install -o root -g root -m 0755 aws-iam-authenticator /usr/local/bin/aws-iam-authenticator

COPY  . /AdKS

WORKDIR /AdKS

# Builds binary
RUN make build

# Code file to execute when the docker container starts up (`entrypoint.sh`)
ENTRYPOINT ["/AdKS/entrypoint.sh"]
