#!/usr/bin/env bash
echo "Starting plugin build"
#sudo su

echo "Docker cleanup"
docker rm `docker ps -qa`
docker image prune -f
docker volume prune -f

#sudo systemctl restart docker.service

echo "Disabling the plugin if it exists"
docker plugin disable solarwinds/papertrail-plugin

echo "Removing the plugin if it exists"
docker plugin rm solarwinds/papertrail-plugin


#######################
echo "Executable cleanup"
rm -f docker-papertrail-log-driver
#go clean

echo "Building executable"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o output/docker-papertrail-log-driver
#######################





echo "cleanup"
rm -rf papertrail/

echo "Recreating directory structure"
mkdir -p papertrail/rootfs

echo "Copying configs"
cp config.json papertrail/

echo "Building docker image"
docker build -t rootfsimage -f output/Dockerfile.build output/

echo "Executable cleanup"
rm -f docker-papertrail-log-driver

echo "Creating a container with the image"
id=$(docker create rootfsimage true)

echo "Exporting the container fs"
docker export "$id" > rootfs.tar
docker rm -vf "$id"
docker rmi rootfsimage

echo "Extracting the tar'd root fs"
sudo tar -x --owner root --group root --no-same-owner -C papertrail/rootfs < rootfs.tar

echo "Removing the tar file"
rm -f rootfs.tar

echo "Setting the plugin up"
docker plugin create solarwinds/papertrail-plugin papertrail/

echo "Enabling the plugin"
docker plugin enable solarwinds/papertrail-plugin

#sudo systemctl restart docker.service

echo "All done. Please proceed to use the log plugin."

# for logs: journalctl -u docker.service -f
# test container: docker run --rm --log-driver solarwinds/papertrail-plugin --log-opt papertrail-url=logs6.papertrailapp.com:22782 --log-opt papertrail-token=3usY2t96ZRtACypjcC2z ubuntu bash -c 'while true; do date +%s%N | sha256sum | base64 | head -c 32 ; echo " - Hello world"; sleep 10; done'