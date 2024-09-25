provider "aws" {
  region = "us-west-2"
}

# Vulnerability 1: Publicly Accessible S3 Bucket
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "my-vulnerable-bucket"

  acl    = "public-read"  # Public access, vulnerable configuration

  versioning {
    enabled = true
  }

  tags = {
    Name        = "Vulnerable S3 Bucket"
    Environment = "Test"
  }
}

# Vulnerability 2: Public Access Not Blocked
resource "aws_s3_bucket_public_access_block" "public_access_block" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  block_public_acls       = false  # Vulnerability: Public ACLs allowed
  block_public_policy     = false  # Vulnerability: Public bucket policy allowed
  ignore_public_acls      = false  # Vulnerability: Does not ignore public ACLs
  restrict_public_buckets = false  # Vulnerability: Public access not restricted
}

# Vulnerability 3: Insecure Security Group
resource "aws_security_group" "vulnerable_sg" {
  name        = "vulnerable_sg"
  description = "Security group with open ports"

  ingress {
    description = "Allow all inbound traffic (VERY INSECURE)"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Vulnerability: Allows traffic from all IPs
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Insecure Security Group"
  }
}

# Vulnerability 4: Insecure EC2 Instance Configuration
resource "aws_instance" "vulnerable_instance" {
  ami           = "ami-0c55b159cbfafe1f0"  # Example AMI (ensure to check AMI security)
  instance_type = "t2.micro"

  # Vulnerability: Instance is exposed to the internet due to public IP and security group rules
  associate_public_ip_address = true  # Public IP assigned to the instance

  vpc_security_group_ids = [aws_security_group.vulnerable_sg.id]  # Using insecure SG

  tags = {
    Name = "Vulnerable EC2 Instance"
  }
}

# Vulnerability 5: Hardcoded Secrets in Code
resource "aws_db_instance" "vulnerable_db" {
  allocated_storage    = 20
  storage_type         = "gp2"
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro"
  name                 = "vulnerabledb"
  username             = "root"
  
  # Vulnerability: Hardcoded password in Terraform configuration
  password             = "InsecurePassword123!"  # Hardcoded password
  
  publicly_accessible  = true  # Vulnerability: Publicly accessible database

  skip_final_snapshot  = true

  tags = {
    Name = "Vulnerable DB"
  }
}

# Vulnerability 6: Weak IAM Role with Privileges Escalation Potential
resource "aws_iam_role" "vulnerable_role" {
  name = "vulnerable_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action    = "sts:AssumeRole",
      Effect    = "Allow",
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })

  # Vulnerability: Excessive privileges granted in the policy
  inline_policy {
    name = "excessive_privileges"
    policy = jsonencode({
      Version = "2012-10-17",
      Statement = [{
        Action = "*",  # Vulnerability: Wildcard action grants all permissions
        Effect = "Allow",
        Resource = "*"
      }]
    })
  }

  tags = {
    Name = "Vulnerable IAM Role"
  }
}

