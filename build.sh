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

echo "Logging in to Docker"
docker login -e $DOCKER_EMAIL -u $DOCKER_USER -p $DOCKER_PASS

echo "Publishing plugin"
docker plugin push solarwinds/papertrail-plugin