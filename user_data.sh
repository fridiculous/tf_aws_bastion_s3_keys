#!/usr/bin/env bash

##############
# Install deps
##############
# Ubuntu
apt-get update
apt-get install python-pip jq -y
#####################

# Amazon Linux (RHEL) - NAT instances
yum update -y
# epel provides python-pip & jq
yum install -y epel-release
yum install python-pip jq -y
#####################

pip install --upgrade awscli

##############


# Copied from the AWS Blog
# https://aws.amazon.com/blogs/security/how-to-record-ssh-sessions-established-through-a-bastion-host/#more-1049

# Create a new folder for the log files
mkdir /var/log/bastion

# Allow ec2-user only to access this folder and its content
chown ubuntu:ubuntu /var/log/bastion
chmod -R 770 /var/log/bastion
setfacl -Rdm other:0 /var/log/bastion

# Make OpenSSH execute a custom script on logins
echo -e "\nForceCommand /usr/bin/bastion/shell" >> /etc/ssh/sshd_config

# Block some SSH features that bastion host users could use to circumvent 
# the solution
awk '!/AllowTcpForwarding/' /etc/ssh/sshd_config > temp && mv temp /etc/ssh/sshd_config
awk '!/X11Forwarding/' /etc/ssh/sshd_config > temp && mv temp /etc/ssh/sshd_config
echo "AllowTcpForwarding no" >> /etc/ssh/sshd_config
echo "X11Forwarding no" >> /etc/ssh/sshd_config

mkdir /usr/bin/bastion

cat > /usr/bin/bastion/shell << 'EOF'

# Check that the SSH client did not supply a command
if [[ -z $SSH_ORIGINAL_COMMAND ]]; then

  # The format of log files is /var/log/bastion/YYYY-MM-DD_HH-MM-SS_user
  LOG_FILE="`date --date="today" "+%Y-%m-%d_%H-%M-%S"`_`whoami`"
  LOG_DIR="/var/log/bastion/"

  # Print a welcome message
  echo ""
  echo "    Welcome to Fridiculous' Bastion     "
  echo "----------------------------------------"
  echo "Note: This SSH session is being recorded"
  echo "Audit Key: $LOG_FILE"
  echo ""

  # I suffix the log file name with a random string. I explain why 
  # later on.
  SUFFIX=`mktemp -u _XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`

  # Wrap an interactive shell into "script" to record the SSH session
  script -qf --timing=$LOG_DIR$LOG_FILE$SUFFIX.time $LOG_DIR$LOG_FILE$SUFFIX.data --command=/bin/bash

else

  # The "script" program could be circumvented with some commands 
  # (e.g. bash, nc). Therefore, I intentionally prevent users 
  # from supplying commands.

  echo "This bastion supports interactive sessions only. Do not supply a command"
  exit 1

fi

EOF

# Make the custom script executable
chmod a+x /usr/bin/bastion/shell

# Bastion host users could overwrite and tamper with an existing log file 
# using "script" if they knew the exact file name. I take several measures 
# to obfuscate the file name:
# 1. Add a random suffix to the log file name.
# 2. Prevent bastion host users from listing the folder containing log 
# files. 
# This is done by changing the group owner of "script" and setting GID.
chown root:ubuntu /usr/bin/script
chmod g+s /usr/bin/script

# 3. Prevent bastion host users from viewing processes owned by other 
# users, because the log file name is one of the "script" 
# execution parameters.
mount -o remount,rw,hidepid=2 /proc
awk '!/proc/' /etc/fstab > temp && mv temp /etc/fstab
echo "proc /proc proc defaults,hidepid=2 0 0" >> /etc/fstab

# Restart the SSH service to apply /etc/ssh/sshd_config modifications.
service sshd restart

#######

# Bastion host users should log in to the bastion host with 
# their personal SSH key pair. The public keys are stored on 
# S3 with the following naming convention: "username.pub". This 
# script retrieves the public keys, creates or deletes local user 
# accounts as needed, and copies the public key to 
# /home/username/.ssh/authorized_keys

# create /usr/bin/bastion/sync_s3
cat > /usr/bin/bastion/sync_users << 'EOF'
# Copy log files to S3 with server-side encryption enabled.
# Then, if successful, delete log files that are older than a day.
LOG_DIR="/var/log/bastion/"
S3_BASTION_BUCKET=${s3_bucket_name}
aws s3 cp $LOG_DIR s3://$S3_BASTION_BUCKET/logs/ --sse --region region --recursive && find $LOG_DIR* -mtime +1 -exec rm {} \;

EOF

#####

# create /usr/bin/bastion/sync_s3
cat > /usr/bin/bastion/sync_s3 << 'EOF'
S3_BASTION_BUCKET=${s3_bucket_name}
BASTION_PUBLIC_KEYS_FOLDER=public_keys

# The file will log user changes
LOG_FILE="/var/log/bastion/users_changelog.txt"

# The function returns the user name from the public key file name.
# Example: public-keys/sshuser.pub => sshuser
get_user_name () {
  echo "$1" | sed -e 's/.*\///g' | sed -e 's/\.pub//g'
}

# For each public key available in the S3 bucket
aws s3api list-objects --bucket $S3_BASTION_BUCKET --region us-east-2 --prefix $BASTION_PUBLIC_KEYS_FOLDER --output text --query 'Contents[?Size>`0`].Key' | sed -e 'y/\t/\n/' > /home/ubuntu/keys_retrieved_from_s3
while read line; do
  USER_NAME="`get_user_name "$line"`"

  # Make sure the user name is alphanumeric
  if [[ "$USER_NAME" =~ ^[a-z][-a-z0-9]*$ ]]; then

    # Create a user account if it does not already exist
    cut -d: -f1 /etc/passwd | grep -qx $USER_NAME
    if [ $? -eq 1 ]; then
      /usr/sbin/useradd $USER_NAME -g dev -p changeme && \
      mkdir -m 700 /home/$USER_NAME/.ssh && \
      chown $USER_NAME:$USER_NAME /home/$USER_NAME/.ssh && \
      echo "$line" >> ~/keys_installed && \
      echo "`date --date="today" "+%Y-%m-%d %H-%M-%S"`: Creating user account for $USER_NAME ($line)" >> $LOG_FILE
    fi

    # Copy the public key from S3, if a user account was created 
    # from this key
    if [ -f ~/keys_installed ]; then
      grep -qx "$line" ~/keys_installed
      if [ $? -eq 0 ]; then
        aws s3 cp s3://$S3_BASTION_BUCKET/$line /home/$USER_NAME/.ssh/authorized_keys --region us-east-2 
        chmod 600 /home/$USER_NAME/.ssh/authorized_keys
        chown $USER_NAME:$USER_NAME /home/$USER_NAME/.ssh/authorized_keys
      fi
    fi

  fi
done < ~/keys_retrieved_from_s3

# Remove user accounts whose public key was deleted from S3
if [ -f ~/keys_installed ]; then
  sort -uo ~/keys_installed ~/keys_installed
  sort -uo ~/keys_retrieved_from_s3 ~/keys_retrieved_from_s3
  comm -13 ~/keys_retrieved_from_s3 ~/keys_installed | sed "s/\t//g" > ~/keys_to_remove
  while read line; do
    USER_NAME="`get_user_name "$line"`"
    echo "`date --date="today" "+%Y-%m-%d %H-%M-%S"`: Removing user account for $USER_NAME ($line)" >> $LOG_FILE
    /usr/sbin/userdel -r -f $USER_NAME
  done < ~/keys_to_remove
  comm -3 ~/keys_installed ~/keys_to_remove | sed "s/\t//g" > ~/tmp && mv ~/tmp ~/keys_installed
fi
EOF



#######

chmod 700 /usr/bin/bastion/sync_users
chmod 700 /usr/bin/bastion/sync_s3

cat > ~/mycron << EOF
${keys_update_frequency} /usr/bin/bastion/sync_s3
${keys_update_frequency} /usr/bin/bastion/sync_users
# 0 0 * * * yum -y update --security
EOF
crontab ~/mycron
rm ~/mycron



# cat <<"EOF" > /home/${ssh_user}/update_ssh_authorized_keys.sh
# #!/usr/bin/env bash

# set -e

# BUCKET_NAME=${s3_bucket_name}
# BUCKET_URI=${s3_bucket_uri}
# SSH_USER=${ssh_user}
# MARKER="# KEYS_BELOW_WILL_BE_UPDATED_BY_TERRAFORM"
# KEYS_FILE=/home/$SSH_USER/.ssh/authorized_keys
# TEMP_KEYS_FILE=$(mktemp /tmp/authorized_keys.XXXXXX)
# PUB_KEYS_DIR=/home/$SSH_USER/pub_key_files/
# PATH=/usr/local/bin:$PATH

# [[ -z $BUCKET_URI ]] && BUCKET_URI="s3://$BUCKET_NAME/"

# mkdir -p $PUB_KEYS_DIR

# # Add marker, if not present, and copy static content.
# grep -Fxq "$MARKER" $KEYS_FILE || echo -e "\n$MARKER" >> $KEYS_FILE
# line=$(grep -n "$MARKER" $KEYS_FILE | cut -d ":" -f 1)
# head -n $line $KEYS_FILE > $TEMP_KEYS_FILE

# # Synchronize the keys from the bucket.
# aws s3 sync --delete $BUCKET_URI $PUB_KEYS_DIR
# for filename in $PUB_KEYS_DIR/*; do
#     sed 's/\n\?$/\n/' < $filename >> $TEMP_KEYS_FILE
# done

# # Move the new authorized keys in place.
# chown $SSH_USER:$SSH_USER $KEYS_FILE
# chmod 600 $KEYS_FILE
# mv $TEMP_KEYS_FILE $KEYS_FILE
# if [[ $(command -v "selinuxenabled") ]]; then
#     restorecon -R -v $KEYS_FILE
# fi
# EOF

# cat <<"EOF" > /home/${ssh_user}/.ssh/config
# Host *
#     StrictHostKeyChecking no
# EOF
# chmod 600 /home/${ssh_user}/.ssh/config
# chown ${ssh_user}:${ssh_user} /home/${ssh_user}/.ssh/config

# chown ${ssh_user}:${ssh_user} /home/${ssh_user}/update_ssh_authorized_keys.sh
# chmod 755 /home/${ssh_user}/update_ssh_authorized_keys.sh

# # Execute now
# su ${ssh_user} -c /home/${ssh_user}/update_ssh_authorized_keys.sh

# # Be backwards compatible with old cron update enabler
# if [ "${enable_hourly_cron_updates}" = 'true' -a -z "${keys_update_frequency}" ]; then
#   keys_update_frequency="0 * * * *"
# else
#   keys_update_frequency="${keys_update_frequency}"
# fi

# # Add to cron
# if [ -n "$keys_update_frequency" ]; then
#   croncmd="/home/${ssh_user}/update_ssh_authorized_keys.sh"
#   cronjob="$keys_update_frequency $croncmd"
#   ( crontab -u ${ssh_user} -l | grep -v "$croncmd" ; echo "$cronjob" ) | crontab -u ${ssh_user} -
# fi

# Append addition user-data script
# ${additional_user_data_script}
