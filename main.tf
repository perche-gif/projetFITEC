provider "aws" {
  region = "eu-west-2"
}

variable "key_name" {
  default = "ppwp-fitec"
}

variable "user_login" {
  default = "admin"
}

variable "user_password" {
  default = "admin2020"
}

variable "db_name" {
  default = "pptf_rds_wp_db"
}

variable "app_port" {
  default = 80
}

variable "vpc_id" {
  default = "vpc-6c87d604"
}

resource "aws_key_pair" "ppwp-fitec" {
key_name = var.key_name
public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC57A17EyuGZBiuylgQlJAKJrIp0av18dyxMvPf2yCddg7LYc+viY5rxxfl/PutKphOiIed3mF4edwE0x0q1hQPhJ2l0l//xLiLiTSZ3am4eRwZKJSdYwQrIDZOVCX5Pdm3JI73Xgawb64KHY1i+fXxuF1hPPbw1D84IuTJsGbzdGeIn+6MNhhNLk8y+H/t/WQpWSml4yfhvMIJ3n3TIqyln8KfdqbJTUR1naDB54w2oVB1TgLNfpwhlg0Uwy1Cu7owjXefgu9lTCEiPBK5Y4A92joD/poZqtez14tiaKCgbLUEGTYrJRDv6tTubZn3ZbR13tLnIwDW0ytmkkBlxYcYAFuUiUtsj2mf49mtW8dOY9KqVCQHqhuHdo2M61aIVB5CiNUbrk0Zd90NQSmQZfOKDAYAP/nmWE7xip2ntPpVUGgA8ddykW7EAnZ1IHKBUiYt8HpdeJ11+VbLTKXGot9iQiOy1Lw+GbJdXzRX50IFYUWFjipdoGL6EtuIGAPxAPE= fitec@FITEC"
}

#Create lanch configuration
resource "aws_launch_configuration" "pptf_wp_fitec" {
  name            = "pptf_wordpress_fitec_2"
  image_id        = "ami-05c424d59413a2876" #"ami-0503f20a49ad915eb"
  instance_type   = "t2.micro"
  security_groups = [aws_security_group.pptf_allow_worpress_http.id]
  key_name        = var.key_name

  user_data = <<-EOF
              #!/bin/bash
              apt update
              apt install apache2 php php-mysql php-curl unzip -y
              rm -rf /var/www/html/index.html
              wget https://fr.wordpress.org/latest-fr_FR.zip
              unzip latest-fr_FR.zip
              mv wordpress/* /var/www/html/
              chown -R www-data:www-data /var/www/html
              cd /var/www/html
              cp wp-config-sample.php wp-config.php
              sed "s/^define( 'DB_NAME'.*/define( 'DB_NAME', '${var.db_name}' );/g" wp-config.php > wp-config-1.php
              sed "s/^define( 'DB_USER'.*/define( 'DB_USER', '${var.user_login}' );/g" wp-config-1.php > wp-config-2.php
              sed "s/^define( 'DB_PASSWORD'.*/define( 'DB_PASSWORD', '${var.user_password}' );/g" wp-config-2.php > wp-config-3.php
              sed "s/^define( 'DB_HOST'.*/define( 'DB_HOST', '${aws_db_instance.pptf_rds_wp.endpoint}' );/g" wp-config-3.php > wp-config-4.php
              rm wp-config.php 
              mv wp-config-4.php wp-config.php
              rm wp-config-*.php               
              EOF
}

#Create Security Group for ec2 instance
resource "aws_security_group" "pptf_allow_worpress_http" {
  name = "ppallow-wp-instance-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = var.app_port
    to_port     = var.app_port
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
    Name = "pptf_allow_wordpress_http"
  }

}

#Create autoscaling group
resource "aws_autoscaling_group" "pptf_asg_wordpress" {
  name                      = "pptf-asg-wordpress-fitec"
  launch_configuration      = aws_launch_configuration.pptf_wp_fitec.name
  min_size                  = 2
  max_size                  = 10
  health_check_grace_period = 300
  health_check_type         = "ELB"
  desired_capacity          = 2
  target_group_arns         = [aws_lb_target_group.pptf_wp_tg.arn]
  vpc_zone_identifier       = ["subnet-71cd783d", "subnet-78a6fd11", "subnet-d8a8cfa2"]

  lifecycle {
    create_before_destroy = true
  }

  tag {
    key                 = "Name"
    value               = "pptf_instance_from_asg"
    propagate_at_launch = true
  }

}

#Create target group
resource "aws_lb_target_group" "pptf_wp_tg" {
  name     = "pptf-tg-wordpress"
  port     = 80
  protocol = "HTTP"
  vpc_id   = var.vpc_id
}

#Create load balancer
resource "aws_lb" "pptf_lb_wp" {
  name               = "pptf-lb-wordpress"
  load_balancer_type = "application"
  subnets            = ["subnet-71cd783d", "subnet-78a6fd11", "subnet-d8a8cfa2"]
  security_groups    = [aws_security_group.pptf_alb_worpress_http.id]

  tags = {
    Name = "pptf-lb-wordpress"
  }
}


resource "aws_lb_listener_rule" "pptf_asg_rule" {
  listener_arn = aws_lb_listener.pptf_http.arn
  priority     = 100

  condition {
    path_pattern {
      values = ["*"]
    }
  }

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.pptf_wp_tg.arn
  }
}

resource "aws_lb_listener" "pptf_http" {
  load_balancer_arn = aws_lb.pptf_lb_wp.arn
  port              = var.app_port
  protocol          = "HTTP"

  # By default, return a simple 404 page
  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "404: page not found"
      status_code  = 404
    }
  }
}

#Create Security Group for ALB instance
resource "aws_security_group" "pptf_alb_worpress_http" {
  name = "ppalb-wp-instance-sg"

  ingress {
    from_port   = var.app_port
    to_port     = var.app_port
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
    Name = "pptf_alb_wordpress_http"
  }

}
#Edit default security group to add new rule 
resource "aws_security_group_rule" "allo_mysql_port" {
  type                     = "ingress"
  from_port                = 3306
  to_port                  = 3306
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.pptf_allow_worpress_http.id
  security_group_id        = "sg-0e1a077c45568ecae"
}


#Create RDS DB
resource "aws_db_instance" "pptf_rds_wp" {
  allocated_storage    = 20
  storage_type         = "gp2"
  engine               = "mysql"
  engine_version       = "8.0.20"
  instance_class       = "db.t2.micro"
  name                 = "pptf_rds_wp_db"
  username             = "admin"
  password             = "admin2020"
  parameter_group_name = "default.mysql8.0"  
  backup_retention_period = 7
  skip_final_snapshot  = true
}

resource "aws_db_instance" "pprepli" {
  allocated_storage    = 20
  storage_type         = "gp2"
  engine               = "mysql"
  engine_version       = "8.0.20"
  instance_class       = "db.t2.micro"
  name                 = "pptf_rds_wp_db_rep"
  username             = "admin"
  password             = "admin2020"
  parameter_group_name = "default.mysql8.0"
  skip_final_snapshot  = true
  replicate_source_db = "arn:aws:rds:eu-west-2:118268119350:db:terraform-20201104141532343300000001"

} 
#affiche le dsn du load balancer
output "public_elb_dns" {
  value       = aws_lb.pptf_lb_wp.dns_name
  description = "The public dns of the load balancer"
}    