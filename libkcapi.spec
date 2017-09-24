Name:           libkcapi
Version:        0.15.0
Release:        1%{?dist}
URL:            http://www.chronox.de/libkcapi.html

Source0:        libkcapi-%{version}.tar.xz
#Source0:        http://www.chronox.de/libkcapi/libkcapi-%{version}.tar.xz
#Source1:        http://www.chronox.de/libkcapi/libkcapi-%{version}.tar.xz.asc

License:        BSD or GPLv2
Summary:        User space interface to the Linux Kernel Crypto API
BuildRequires:  autoconf automake libtool openssl
BuildRequires:  xmlto
BuildRequires:  fipscheck
Group:          System Environment/Libraries

%package        devel
Summary:        Development files for the %{name} package
License:        BSD or GPLv2
Group:          Development/Libraries
Requires:       %{name}%{?_isa} = %{version}-%{release}

%package        tools
Summary:        Utility applications for the %{name} package
License:        BSD or GPLv2
Group:          System Environment/Libraries
Requires:       %{name}%{?_isa} = %{version}-%{release}

%package        replacements
Summary:        Drop-in replacements provided by the %{name} package
License:        BSD or GPLv2
Group:          System Environment/Libraries
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description    devel
Header files for applications that use %{name}.

%description    tools
Utility applications that are provided with %{name}. This includes
tools to use message digests, symmetric ciphers and random number
generators implemented in the Linux kernel from command line.

%description replacements
Provide drop-in replacements for the sha*sum (coreutils), sha*hmac
(hmaccalc), and fipscheck and fipshmac (fipscheck) tools using %{name}.

%description
libkcapi allows user-space to access the Linux kernel crypto API.

This library uses the netlink interface and exports easy to use APIs
so that a developer does not need to consider the low-level netlink
interface handling.

The library does not implement any cipher algorithms. All consumer
requests are sent to the kernel for processing. Results from the
kernel crypto API are returned to the consumer via the library API.

The kernel interface and therefore this library can be used by
unprivileged processes.

%prep
%autosetup -p1

%build
autoreconf -i
%configure \
        --enable-kcapi-encapp \
        --enable-kcapi-rngapp \
        --enable-kcapi-dgstapp \
        --enable-kcapi-hasher \
        --enable-kcapi-speed
%make_build
make man

%check
fipshmac .libs/libkcapi.so.*

# Add generation of HMAC checksums of the final stripped binaries
%define __spec_install_post \
    %{?__debug_package:%{__debug_install_post}} \
    %{__arch_install_post} \
    %{__os_install_post} \
    fipshmac $RPM_BUILD_ROOT%{_libdir}/*.so.* \
%{nil}

%install
%make_install
rm -f %{buildroot}%{_libdir}/*.a
rm -f %{buildroot}%{_libdir}/*.la
rm -f %{buildroot}%{_bindir}/kcapi-hasher
make install-man DESTDIR=%{buildroot}
gzip %{buildroot}%{_mandir}/man3/*.3

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%license COPYING COPYING.gplv2 COPYING.bsd
%doc README.md CHANGES TODO
%{_libdir}/*.so.*
%{_libdir}/.*.so.*.hmac

%files devel
%doc %{_mandir}/man3/kcapi_*.3*
%{_includedir}/kcapi.h
%{_libdir}/*.so

%files tools
%{_bindir}/kcapi*
%doc %{_mandir}/man1/kcapi*.1*

%files replacements
%{_bindir}/sha*sum
%{_bindir}/.sha*sum.hmac
%{_bindir}/md5sum
%{_bindir}/.md5sum.hmac
%{_bindir}/sha*hmac
%{_bindir}/.sha*hmac.hmac
%{_bindir}/fips*
%{_bindir}/.fips*.hmac


%changelog
* Sun Sep 10 2017 Stephan Mueller <smueller@chronox.de> - 0.15.0-1
- Initial packaging
