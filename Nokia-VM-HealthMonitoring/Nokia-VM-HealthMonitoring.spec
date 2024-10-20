Name:           Nokia-VM-HealthMonitoring
Version:        2.0
Release:        1%{?dist}
Summary:        Health Monitoring for Nokia VM
License:        Unlicensed  # Use "Unlicensed" as a placeholder for the license
Source0:        %{name}-%{version}.tar.gz

%description
This package provides health monitoring functionality for Nokia VMs.

%prep
%setup -q

%build
# Add any build commands here if your application requires compilation
# For example: make

%install
mkdir -p %{buildroot}/opt/nokia/vm-healthmonitoring
cp -r * %{buildroot}/opt/nokia/vm-healthmonitoring/

%files
/opt/nokia/vm-healthmonitoring

%changelog
* Mon Oct 14 2024 Satish Pepakayala <satishpepakayala1999@gmail.com> - 1.0-1
- Initial package
