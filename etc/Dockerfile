FROM gcc

RUN apt-get -y update \
	&& DEBIAN_FRONTEND=noninteractive \
			apt-get install -y -q --no-install-recommends \
				libreadline-dev \
				libtool \
				autoconf-archive \
				net-tools \
				usbutils \
				vim \
				man \
				bsdtar \
				gdb \
				gcc g++ \
				pkg-config
