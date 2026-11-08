output "table_name" {
  description = "Lease table name."
  value       = aws_dynamodb_table.lease.name
}

output "nat_instance_ids" {
  description = "Instance IDs of NAT a and NAT b."
  value       = { for name, nat in aws_instance.nat : name => nat.id }
}

output "nat_public_ips" {
  description = "Each NAT's own Elastic IP, which its own-path probes leave from."
  value       = { for name, eip in aws_eip.nat : name => eip.public_ip }
}

output "shared_eni_id" {
  description = "The shared ENI that moves between the NATs. Point each private route table's 0.0.0.0/0 route at it."
  value       = aws_network_interface.shared.id
}

output "shared_public_ip" {
  description = "The shared Elastic IP that worker traffic leaves through."
  value       = local.shared_public_ip
}

output "receiver_url" {
  description = "Probe receiver URL. The NATs sign their uploads to it with their role's credentials."
  value       = aws_lambda_function_url.receiver.function_url
}
