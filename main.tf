terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.10.0"
    }
  }
}

provider "aws" {
  # Configuration options
}

variable "aws_region" {
  description = "The region where resources will be deployed"
  default     = "us-east-1"
}

resource "aws_s3_bucket" "my-bucket" {
  bucket = "thomas-week-20-luit-blue-bucket-2023"

  tags = {
    Name = "Week 20 bucket"
  }
}

resource "aws_security_group" "jenkins-sg" {
  name        = "jenkins-security-group"
  description = "Allow inbound traffic to Jenkins server"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["54.175.102.108/32"]
  }

  ingress {
    description = "Jenkins"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
#Resource to create a SSH private key
resource "tls_private_key" "jenkins_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "ssh_key" {
  key_name   = "jenkins_ssh"
  public_key = tls_private_key.jenkins_key.public_key_openssh
}


resource "aws_iam_policy" "jenkins_policy" {
  name        = "jenkins_policy"
  path        = "/"
  description = "My jenkins policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Action" : [
          "s3:ListAllMyBuckets"
        ],
        "Effect" : "Allow",
        "Resource" : "arn:aws:s3:::*"
      },
      {
        "Action" : "s3:*",
        "Effect" : "Allow",
        "Resource" : ["arn:aws:s3:::thomas-week-20-luit-blue-bucket-2023", "arn:aws:s3:::thomas-week-20-luit-blue-bucket-2023/*"]
      }
    ]
  })
}

resource "aws_iam_role" "jenkins_role" {
  name = "jenkins_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

resource "aws_iam_instance_profile" "jenkins_profile" {
  name = "jenkins_profile"
  role = "jenkins_role"
}

resource "aws_iam_role_policy_attachment" "jenkins-role-policy-attach" {
  role       = aws_iam_role.jenkins_role.name
  policy_arn = aws_iam_policy.jenkins_policy.arn
}

resource "aws_instance" "jenkins-server" {
  ami                  = "ami-0f9ce67dcf718d332"
  instance_type        = "t2.micro"
  security_groups      = ["jenkins-security-group"]
  key_name             = "jenkins_ssh"
  iam_instance_profile = "jenkins_profile" # Use the IAM instance profile name here
  user_data            = <<EOF
 #!/bin/bash

yum update –y
wget -O /etc/yum.repos.d/jenkins.repo \
    https://pkg.jenkins.io/redhat-stable/jenkins.repo
rpm --import https://pkg.jenkins.io/redhat-stable/jenkins.io-2023.key
yum upgrade -y
amazon-linux-extras install java-openjdk11 -y
yum install jenkins -y
systemctl enable jenkins
systemctl start jenkins
sudo chmod 755 /var/lib/jenkins/secrets
sudo chmod 644 /var/lib/jenkins/secrets/initialAdminPassword

EOF

  tags = {
    Name = "jenkins-server"
  }
}