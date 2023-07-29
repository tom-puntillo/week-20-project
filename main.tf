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

resource "aws_s3_bucket" "example" {
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