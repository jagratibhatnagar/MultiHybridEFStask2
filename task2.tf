# Declaring the provider

provider "aws" {
  region = "ap-south-1"
  profile = "jaggu"
}


# Creating key pair


resource "tls_private_key" "task2key" {
	algorithm = "RSA"  
	rsa_bits = 4096
}

resource "local_file" "keyfile" {
	filename = "C:/Users/Lenovo/Desktop/terra/mytest/task2key.pem"
}

resource "aws_key_pair" "task2key" {
	depends_on = [ tls_private_key.task2key, ]
	key_name = "task2key"
	public_key = tls_private_key.task2key.public_key_openssh
}


# Create Security group with HTTP and SSH

resource "aws_security_group" "security" {
  depends_on = [ aws_key_pair.task2key, ]
  name        = "security"
  description = "Allow SSH , HTTP and NFS traffic"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

 ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

 ingress {
    description = "NFS"
    from_port   = 2049
    to_port     = 2049
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "task2-sg"
  }
}

# Creating Instance

resource "aws_instance" "task2os" {
 depends_on = [
local_file.keyfile,
aws_key_pair.task2key,
tls_private_key.task2key,
]
  ami           = "ami-0447a12f28fddb066"
  instance_type = "t2.micro"
  key_name = aws_key_pair.task2key.key_name
  
  security_groups = [ "${aws_security_group.security.name}" ]

  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.task2key.private_key_pem   
    host     = aws_instance.task2os.public_ip
  }

  provisioner "remote-exec" {
    inline = [
       
      "sudo yum install httpd  php git -y",
      "sudo systemctl restart httpd",
      "sudo systemctl enable httpd",
    ]
  }
  tags = {
    Name = "task2os"
  }
}

#Creating EFS FILE SYSTEM

resource "aws_efs_file_system" "allow_nfs" {
 depends_on =  [ aws_security_group.task2sg,
                aws_instance.task2os,  ] 
  creation_token = "allow_nfs"


  tags = {
    Name = "allow_nfs"
  }
}

#Mounting EFS File System

resource "aws_efs_mount_target" "efsmount" {
 depends_on =  [ aws_efs_file_system.allow_nfs,
                         ] 
  file_system_id = aws_efs_file_system.allow_nfs.id
  subnet_id      = aws_instance.task2os.subnet_id
  security_groups = ["${aws_security_group.task2sg.id}"]
}

#CONFIGURE EC2 FOR EFS MOUNT

resource "null_resource" "null-remote-1"  {
 depends_on = [ 
               aws_efs_mount_target.efsmount,
                  ]
  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.task2key.private_key_pem
    host     = aws_instance.task2os.public_ip
  }
  provisioner "remote-exec" {
      inline = [
        "sudo echo ${aws_efs_file_system.allow_nfs.dns_name}:/var/www/html efs defaults,_netdev 0 0 >> sudo /etc/fstab",
        "sudo mount  ${aws_efs_file_system.allow_nfs.dns_name}:/  /var/www/html",
        "sudo curl https://github.com/jagratibhatnagar/MultiHybridEFStask2/blob/master/index.html > index.html",                                  "sudo cp index.html  /var/www/html/",
      ]
  }
}

# Creating s3 Bucket

resource "aws_s3_bucket" "task2bucket" {
  bucket = "task2bucket"
  acl = "public-read"
provisioner "local-exec" {

     command = "mkdir gitpull | git clone https://github.com/jagratibhatnagar/image gitpull"
}

  tags = {
 Name = "task2bucket"
}
}


# Uploading image in s3 Bucket

resource "aws_s3_bucket_object" "image-pull" {
depends_on = [
    aws_s3_bucket.task2bucket,
]
  bucket = aws_s3_bucket.task2bucket.id 
  key    = "code-wallpapeer-8.jpg"
  acl = "public-read"
  source = "gitpull/code-wallpaper-8.jpg"

}


# Creating cloudFront Distribution

locals {
  s3_origin_id = "myoriginid"
      }
resource "aws_cloudfront_distribution" "s3-distribution" {
origin {
domain_name = aws_s3_bucket.task2bucket.bucket_regional_domain_name
origin_id =  local.s3_origin_id  
custom_origin_config {
        http_port = 80
        https_port = 80
        origin_protocol_policy = "match-viewer"
        origin_ssl_protocols = ["TLSv1", "TLSv1.1", "TLSv1.2"]
         }
      }

 enabled = true
 is_ipv6_enabled = true

 default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]

    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

     viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
    }

   restrictions {
      geo_restriction {
          restriction_type = "none"
     }
   }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

   connection {
      type     = "ssh"
      user     = "ec2-user"
      private_key = file("C:/Users/Lenovo/Desktop/terra/mytest/key1.pem")
      host     = aws_instance.task2os.public_ip
  
      }
}


#INTEGRATION OF CLOUDFRONT WITH EC2

resource "null_resource" "null-remote2" {
 depends_on = [ aws_cloudfront_distribution.s3-distribution, ]
  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.task2key.private_key_pem
    host     = aws_instance.task2os.public_ip
   }
   provisioner "remote-exec" {
      inline = [
      "sudo su << EOF",
      "echo \"<img src='https://${aws_cloudfront_distribution.s3-distribution.domain_name}/${aws_s3_bucket_object.image-pull.key }'>\" >> /var/www/html/index.html",
       "EOF"
   ]
 }

#Getting start of CHROME

resource "null_resource" "null-local3" {
  depends_on = [
      null_resource.null-remote2,
   ]
   provisioner "local-exec" {
         command = "start chrome ${aws_instance.task2os.public_ip}/index.html"
    }
}