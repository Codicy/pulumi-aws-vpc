/*
 * Copyright 2018-2019, James Nugent.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */

import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import { ComponentResource, ComponentResourceOptions, Input, Output } from "@pulumi/pulumi";
import { SubnetDistributor } from "./subnetDistributor";

export interface VpcArgs {
    description: string;
    baseTags: aws.Tags;

    baseCidr: string;
    availabilityZoneNames: string[];
    zoneName?: string;

    natInstancesInsteadOfGateways: boolean;

    endpoints: {
        s3: boolean;
        dynamodb: boolean;
    };
}

export class Vpc extends ComponentResource {
    vpc: aws.ec2.Vpc;
    securityGroup: aws.ec2.SecurityGroup;
    privateZone: aws.route53.Zone;
    dhcpOptionSet: aws.ec2.VpcDhcpOptions;
    internetGateway: aws.ec2.InternetGateway;
    publicSubnets: aws.ec2.Subnet[] = [];
    privateSubnets: aws.ec2.Subnet[] = [];
    publicRouteTable: aws.ec2.RouteTable;
    privateRouteTables: aws.ec2.RouteTable[] = [];
    natGateways: aws.ec2.NatGateway[] = [];
    natInstances: aws.ec2.Instance[] = [];
    natInstanceEipAssociations: aws.ec2.EipAssociation[] = [];
    natElasticIpAddresses: aws.ec2.Eip[] = [];

    flowLogsGroup: aws.cloudwatch.LogGroup;
    flowLogsRole: aws.iam.Role;

    private readonly name: string;
    private readonly description: string;
    private readonly baseTags: { [k: string]: Input<string> };

    constructor(name: string, args: VpcArgs, opts?: ComponentResourceOptions) {
        super("codicy:aws-vpc", name, {}, opts);

        // Make base info available to other methods.
        this.name = name;
        this.description = args.description;
        this.baseTags = args.baseTags;

        // VPC
        this.vpc = new aws.ec2.Vpc(`${name}-vpc`, {
            cidrBlock: args.baseCidr,
            enableDnsSupport: true,
            enableDnsHostnames: true,
            tags: this.resourceTags({
                Name: `${args.description} VPC`,
            }),
        }, { parent: this });

        // Security Group
        this.securityGroup = new aws.ec2.SecurityGroup(`${name}-vpc-sg`, {
            vpcId: this.vpc.id,
            ingress: [
                {
                    fromPort: 0,
                    toPort: 0,
                    protocol: "-1",
                    cidrBlocks: ["0.0.0.0/0"],
                }
            ],
            egress: [
                {
                    fromPort: 0,
                    toPort: 0,
                    protocol: "-1",
                    cidrBlocks: ["0.0.0.0/0"],
                }
            ]
        })

        // Internet Gateway
        this.internetGateway = new aws.ec2.InternetGateway(`${name}-igw`, {
            vpcId: this.vpc.id,
            tags: this.resourceTags({
                Name: `${args.description} VPC Internet Gateway`,
            }),
        }, { parent: this.vpc });

        // Private Hosted Zone and DHCP Options
        if (args.zoneName) {
            this.privateZone = new aws.route53.Zone(`${name}-private-zone`, {
                vpcs: [{
                    vpcId: this.vpc.id,
                }],
                name: args.zoneName,
                comment: `Private zone for ${args.zoneName}. Managed by Pulumi.`,
            }, { parent: this });

            this.dhcpOptionSet = new aws.ec2.VpcDhcpOptions(`${name}-dhcp-options`, {
                domainName: this.privateZone.name,
                domainNameServers: ["AmazonProvidedDNS"],
                tags: this.resourceTags({
                    Name: `${args.description} DHCP Options`,
                }),
            }, { parent: this.vpc });

            new aws.ec2.VpcDhcpOptionsAssociation(`${name}-dhcp-options-assoc`, {
                vpcId: this.vpc.id,
                dhcpOptionsId: this.dhcpOptionSet.id,
            }, { parent: this.dhcpOptionSet });
        }

        // Calculate subnet address spaces and create subnets
        {
            const distributor = new SubnetDistributor(args.baseCidr, args.availabilityZoneNames.length);
            this.publicSubnets = distributor.publicSubnets().map((cidr, index) => {
                return new aws.ec2.Subnet(`${name}-public-${index + 1}`, {
                    vpcId: this.vpc.id,
                    cidrBlock: cidr,
                    mapPublicIpOnLaunch: true,
                    availabilityZone: args.availabilityZoneNames[index],
                    tags: this.resourceTags({
                        Name: `${args.description} Public ${index + 1}`,
                    }),
                }, { parent: this.vpc });
            });
            this.privateSubnets = distributor.privateSubnets().map((cidr, index) => {
                return new aws.ec2.Subnet(`${name}-private-${index + 1}`, {
                    vpcId: this.vpc.id,
                    cidrBlock: cidr,
                    availabilityZone: args.availabilityZoneNames[index],
                    tags: this.resourceTags({
                        Name: `${args.description} Private ${index + 1}`,
                    }),
                }, { parent: this.vpc });
            });
        }

        // Adopt the default route table for the VPC, and adapt it for use with public subnets
        {
            this.publicRouteTable = <aws.ec2.RouteTable>new aws.ec2.DefaultRouteTable(`${name}-public-rt`, {
                defaultRouteTableId: this.vpc.defaultRouteTableId,
                tags: this.resourceTags({
                    Name: `${args.description} Public Route Table`,
                }),
            }, { parent: this.vpc });

            new aws.ec2.Route(`${name}-route-public-sn-to-ig`, {
                routeTableId: this.publicRouteTable.id,
                destinationCidrBlock: "0.0.0.0/0",
                gatewayId: this.internetGateway.id,
            }, { parent: this.publicRouteTable });

            this.publicSubnets.map((subnet, index) => {
                return new aws.ec2.RouteTableAssociation(`${name}-public-rta-${index + 1}`, {
                    subnetId: subnet.id,
                    routeTableId: this.publicRouteTable.id,
                }, { parent: this.publicRouteTable });
            });
        }

        // Create a NAT Gateway and appropriate route table for each private subnet
        for (let index = 0; index < this.privateSubnets.length; index++) {
            const privateSubnet = this.privateSubnets[index];
            const publicSubnet = this.publicSubnets[index];

            this.natElasticIpAddresses.push(new aws.ec2.Eip(`${name}-nat-${index + 1}`, {
                tags: this.resourceTags({
                    Name: `${args.description} NAT Gateway EIP ${index + 1}`,
                }),
            }, { parent: privateSubnet }));

            if (args.natInstancesInsteadOfGateways) {
                const ami = pulumi.output(aws.ec2.getAmi({
                    filters: [{
                        name: "name",
                        values: ["amzn-ami-vpc-nat-*"],
                    }],
                    owners: ["137112412989"], // This owner ID is Amazon
                    mostRecent: true,
                }));
                this.natInstances.push(new aws.ec2.Instance(`${name}-nat-instance-${index + 1}`, {
                    instanceType: "t3.nano",
                    ami: ami.id,
                    subnetId: publicSubnet.id,
                    vpcSecurityGroupIds: [this.securityGroup.id],
                    sourceDestCheck: false,
                    tags: this.resourceTags({
                        Name: `${args.description} NAT Instance ${index + 1}`,
                    }),
                    userData: `#!/bin/bash
                               yum erase -y sendmail
                               echo 1 > /proc/sys/net/ipv4/ip_forward
                               echo 0 > /proc/sys/net/ipv4/conf/eth0/send_redirects
                               /sbin/iptables -t nat -A POSTROUTING -o eth0 -s ${publicSubnet.cidrBlock} -j MASQUERADE
                               /sbin/iptables-save > /etc/sysconfig/iptables
                               mkdir -p /etc/sysctl.d/
                               cat << NatConfFileMarker > /etc/sysctl.d/nat.conf
                               net.ipv4.ip_forward = 1
                               net.ipv4.conf.eth0.send_redirects = 0
                               NatConfFileMarker`
                }));
                this.natInstanceEipAssociations.push(new aws.ec2.EipAssociation(`${name}-nat-instance-${index + 1}-eipAssoc`, {
                    instanceId: this.natInstances[index].id,
                    allocationId: this.natElasticIpAddresses[index].id
                }));
            } else {
                this.natGateways.push(new aws.ec2.NatGateway(`${name}-nat-gateway-${index + 1}`, {
                    allocationId: this.natElasticIpAddresses[index].id,
                    subnetId: publicSubnet.id,
                    tags: this.resourceTags({
                        Name: `${args.description} NAT Gateway ${index + 1}`,
                    }),
                }, { parent: privateSubnet }));
            }

            this.privateRouteTables.push(new aws.ec2.RouteTable(`${name}-private-rt-${index + 1}`, {
                vpcId: this.vpc.id,
                tags: this.resourceTags({
                    Name: `${args.description} Private Subnet RT ${index + 1}`,
                }),
            }, { parent: privateSubnet }));

            if (args.natInstancesInsteadOfGateways) {
                new aws.ec2.Route(`${name}-route-private-sn-to-nat-${index + 1}`, {
                    routeTableId: this.privateRouteTables[index].id,
                    destinationCidrBlock: "0.0.0.0/0",
                    instanceId: this.natInstances[index].id,
                }, { parent: this.privateRouteTables[index] });
            } else {
                new aws.ec2.Route(`${name}-route-private-sn-to-nat-${index + 1}`, {
                    routeTableId: this.privateRouteTables[index].id,
                    destinationCidrBlock: "0.0.0.0/0",
                    natGatewayId: this.natGateways[index].id,
                }, { parent: this.privateRouteTables[index] });
            }

            new aws.ec2.RouteTableAssociation(`${name}-private-rta-${index + 1}`, {
                subnetId: privateSubnet.id,
                routeTableId: this.privateRouteTables[index].id,
            }, { parent: this.privateRouteTables[index] });
        }

        // Create gateway endpoints if necessary
        if (args.endpoints.s3) {
            new aws.ec2.VpcEndpoint(`${name}-s3-endpoint`, {
                vpcId: this.vpc.id,
                serviceName: `com.amazonaws.${aws.config.region}.s3`,
                routeTableIds: [this.publicRouteTable.id, ...this.privateRouteTables.map(x => x.id)],
            }, { parent: this.vpc });
        }

        if (args.endpoints.dynamodb) {
            new aws.ec2.VpcEndpoint(`${name}-dynamodb-endpoint`, {
                vpcId: this.vpc.id,
                serviceName: `com.amazonaws.${aws.config.region}.dynamodb`,
                routeTableIds: [this.publicRouteTable.id, ...this.privateRouteTables.map(x => x.id)],
            }, { parent: this.vpc });
        }

        this.registerOutputs({});
    }

    public enableFlowLoggingToCloudWatchLogs(trafficType: Input<"ALL" | "ACCEPT" | "REJECT">) {
        this.flowLogsRole = new aws.iam.Role(`${this.name}-flow-logs-role`, {
            description: `${this.description} VPC Flow Logs`,
            assumeRolePolicy: aws.iam.assumeRolePolicyForPrincipal(aws.iam.Principals.VpcFlowLogsPrincipal),
        }, { parent: this.vpc });

        this.flowLogsGroup = new aws.cloudwatch.LogGroup(`${this.name}-vpc-flow-logs`, {
            tags: this.resourceTags({
                Name: `${this.description} VPC Flow Logs`,
            }),
        }, { parent: this.flowLogsRole });

        new aws.iam.RolePolicy(`${this.name}-flow-log-policy`, {
            name: "vpc-flow-logs",
            role: this.flowLogsRole.id,
            policy: {
                Version: "2012-10-17",
                Statement: [
                    {
                        Effect: "Allow",
                        Resource: "*",
                        Action: [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                            "logs:DescribeLogGroups",
                            "logs:DescribeLogStreams",
                        ],
                    },
                ],
            },
        }, { parent: this.flowLogsRole });

        new aws.ec2.FlowLog(`${this.name}-flow-logs`, {
            logDestination: this.flowLogsGroup.arn,
            iamRoleArn: this.flowLogsRole.arn,
            vpcId: this.vpc.id,
            trafficType: trafficType,
        }, { parent: this.flowLogsRole });
    }

    public privateSubnetIds(): Output<string>[] {
        return this.privateSubnets.map(x => x.id);
    }

    public publicSubnetIds(): Output<string>[] {
        return this.publicSubnets.map(x => x.id);
    }

    public vpcId(): Output<string> {
        return this.vpc.id;
    }

    public securityGroupId(): Output<string> {
        return this.securityGroup.id;
    }

    private resourceTags(additionalTags: { [k: string]: Input<string> }) {
        return Object.assign(additionalTags, this.baseTags);
    }
}
