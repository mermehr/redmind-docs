### Footprinting:

`sudo nmap 10.129.14.128 -p111,2049 -sV -sC`

`sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049`

### Show Available NFS Shares and mount

`showmount -e 10.129.14.128`

`sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock`

`ls -n mnt/nfs/`

`ls -l mnt/nfs/`