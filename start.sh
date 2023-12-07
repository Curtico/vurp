sysctl -w kernel.core_pattern=core.%p
git config core.sshCommand 'ssh -i /id_rsa'
git clone git@github.com:Curtico/vurp.git
cp /ctfd_access_token /vurp/
pushd vurp
python3 vurp.py
