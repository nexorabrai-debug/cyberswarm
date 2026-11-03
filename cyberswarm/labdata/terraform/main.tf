# LAB ONLY - intentionally insecure, fake credentials
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAFAKEFAKEFAKE1234"
  secret_key = "fake-secret-not-real-0000"
}
resource "aws_s3_bucket" "data" {
  bucket = "lab-public-bucket"
  acl    = "public-read"
}
resource "aws_s3_bucket_public_access_block" "data" {
  bucket            = aws_s3_bucket.data.id
  block_public_acls = false
}
resource "aws_security_group" "ssh" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_security_group" "web" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_db_instance" "db" {
  password = "SuperFakeLabPass123"
}
variable "ok_var" {
  default = "${var.not_a_secret_reference}"
}
