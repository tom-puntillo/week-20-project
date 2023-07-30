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
    cidr_blocks = ["0.0.0.0/0"]
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

variable "key_name" {
  type    = string
  default = "my_jenkins_key"
}

variable "public_key" {
  type    = string
  default = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC9NCLFhVhLKq1MlCBHvsf+Ch9cn8vKkgjQdgzNZMnGCURnKnbuVLWJUqQhi1OEufXS6AjBFNs6QvczuNm/mJDGZbUAYtiZxS6C6oxFIOPxA8RgDDSf8qaLQDjvgFlWe5aRSld1Yr812klRJN/464SyBURZvDfUD8/nEF7G1/268nHJRyvv2/Pok71bduK6cYEHo8HguYsMhhdMnCwL6Gk/Vmbh0fkBx5Cd+8SeDg7eI1lZDrjwq83p4UuIJ02e0f5ew4eC5itwVh/DfnXDMk0Q8edNWS6h6PfJTQFL85+W9vUGlOBEXlYaiQPP0MRA/T7t4umIHbsS0UwhEqtJQDRPBVXK7DviKBNkjWqb2ursPMloGICjqyDDHVA+cNYFeFZqiO28/bY0+s40MHrl1oBvKwLREpAlVj3FoToTpoKNTZbJ9OPPRBhlSL3vQF8y0ELwzX7ZHQ2aIBGH628GYct85vNVeGt5U3SpA2/zeJI8R3NBu7JQNbSUs2oUyMJl1yQZZmD3bmY1z70uO1LGHLNxQWtFmvbR0LCK5qzeZ7lNqYpqTUUyYln/+Xf1WF+dfiayCfaWy0f8cJBkyFvX+hUj2as3kQF+wx4Ds+r/9UvxhXM4ISooJ0fk8xUzq0FgB5rAwO4dFceXVzwNs+GoakhE77EgQ5KnbZUYwOijGLwnSw== ec2-user@ip-172-31-50-89.ec2.internal"
}

resource "aws_key_pair" "ssh_key" {
  key_name   = var.key_name
  public_key = var.public_key
}

data "aws_ami" "amazon_linux_2" {
  most_recent = true

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-2.0.*-x86_64-gp2"]
  }

  owners = ["amazon"]
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
  ami                  = data.aws_ami.amazon_linux_2.id
  instance_type        = "t2.micro"
  security_groups      = ["jenkins-security-group"]
  key_name             = aws_key_pair.ssh_key.key_name
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
