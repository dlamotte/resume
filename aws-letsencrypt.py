#!/usr/bin/env python

from cStringIO import StringIO
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
import OpenSSL.crypto
import acme.challenges
import acme.client
import acme.jose
import argparse
import boto3
import botocore
import sys
import time

ACME_DIR_PRODUCTION_URL = 'https://acme-v01.api.letsencrypt.org/directory'
ACME_DIR_TESTING_URL = 'https://acme-staging.api.letsencrypt.org/directory'

class Client(object):
    MIN_DAYS_LEFT = timedelta(days=45)

    def __init__(self,
        cloudfront_client,
        iam_client,
        route53_client,
        s3resource,
        is_production,
        s3bucket,
        email
    ):
        self.cf = cloudfront_client
        self.iam = iam_client
        self.r53 = route53_client
        self.s3 = s3resource

        self.is_production = is_production
        self.s3bucket = s3bucket
        self.email = email

        self.acme_client = None
        self.key = None

    def route53_change(self, action, zone_id, domain, value):
        return self.r53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                'Changes': [
                    {
                        'Action': action,
                        'ResourceRecordSet': {
                            'Name': domain,
                            'Type': 'TXT',
                            'TTL': 30,
                            'ResourceRecords': [
                                {
                                    'Value': '"' + value + '"',
                                }
                            ],
                        }
                    }
                ]
            }
        )['ChangeInfo']['Id']

    def route53_create(self, zone_id, domain, value):
        return self.route53_change('CREATE', zone_id, domain, value)

    def route53_delete(self, zone_id, domain, value):
        return self.route53_change('DELETE', zone_id, domain, value)

    def setup(self):
        acme_url = ACME_DIR_TESTING_URL
        key_name = 'testing.pem'
        if self.is_production:
            acme_url = ACME_DIR_PRODUCTION_URL
            key_name = 'production.pem'

        s3obj = self.s3.Object(self.s3bucket, key_name)
        try:
            s3obj.load()
        except botocore.exceptions.ClientError as exc:
            if exc.response['Error']['Code'] == "404":
                exists = False
            else:
                raise
        else:
            exists = True

        if not exists:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )

            acme_client = acme.client.Client(
                acme_url,
                key=acme.jose.JWKRSA(key=private_key)
            )
            registration = acme_client.register(
                acme.messages.NewRegistration.from_data(email=self.email)
            )
            acme_client.agree_to_tos(registration)

            pem = StringIO()
            pem.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
            pem.seek(0)

            s3obj.put(Body=pem)

        s3obj.load()
        key = s3obj.get()['Body'].read()
        self.key = serialization.load_pem_private_key(
            key.encode("utf-8"),
            password=None,
            backend=default_backend()
        )
        self.acme_client = acme.client.Client(
            acme_url,
            key=acme.jose.JWKRSA(key=self.key)
        )

    def update_cert(self, cloudfront_id, domain, force=False):
        if not self.acme_client:
            raise Exception('Client not .setup() yet')

        if self.is_production:
            type_name = 'prod'
        else:
            type_name = 'test'

        iam_cert_names = (
            domain + '-' + type_name + '-a',
            domain + '-' + type_name + '-b',
        )
        iam_certs = {}
        for name in iam_cert_names:
            try:
                iam_certs[name] = {
                    'resp': self.iam.get_server_certificate(
                        ServerCertificateName=name
                    )
                }
            except botocore.exceptions.ClientError as exc:
                if exc.response['ResponseMetadata']['HTTPStatusCode'] != 404:
                    raise

        dist = self.cf.get_distribution(Id=cloudfront_id)
        config = dist['Distribution']['DistributionConfig']

        iam_cert_id = config['ViewerCertificate'].get('IAMCertificateId')
        needs_cert = force or not iam_cert_id
        for name, obj in iam_certs.iteritems():
            obj['cert'] = x509.load_pem_x509_certificate(
                obj['resp']['ServerCertificate']['CertificateBody'],
                default_backend()
            )

            obj['days_left'] = obj['cert'].not_valid_after - datetime.today()
            obj['reissue'] = obj['days_left'] < self.MIN_DAYS_LEFT
            obj['active'] = iam_cert_id == \
                obj['resp'] \
                ['ServerCertificate'] \
                ['ServerCertificateMetadata'] \
                ['ServerCertificateId']

            if obj['active'] and obj['reissue']:
                needs_cert = True

        def sort_best_cert_last(name):
            if name in iam_certs:
                return iam_certs[name]['days_left']

            else:
                return timedelta(days=0)

        next_cert_name = None
        if needs_cert:
            for name in sorted(
                iam_cert_names,
                key=sort_best_cert_last
            ):
                try:
                    obj = iam_certs[name]
                except KeyError:
                    obj = None

                if obj:
                    if obj['active']:
                        continue

                    if force or obj['reissue']:
                        self.iam.delete_server_certificate(
                            ServerCertificateName=name
                        )
                        del obj[name]

                next_cert_name = name

        iam_cert_id_new = None
        if next_cert_name in iam_certs:
            iam_cert_id_new = \
                iam_certs[next_cert_name] \
                ['resp'] \
                ['ServerCertificate'] \
                ['ServerCertificateMetadata'] \
                ['ServerCertificateId']

        if needs_cert and iam_cert_id_new is None:
            print 'requesting new cert ({}) ...'.format(next_cert_name)

            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )

            csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
                x509.Name([
                    x509.NameAttribute(x509.NameOID.COMMON_NAME, domain),
                ])
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(domain),
                ]),
                critical=False,
            )
            csr = csr_builder.sign(
                private_key,
                hashes.SHA256(),
                default_backend()
            )

            authz = self.acme_client.request_domain_challenges(domain)

            # find dns challenge
            chall = filter(
                lambda x: isinstance(x[0].chall, acme.challenges.DNS01),
                authz.body.resolved_combinations
            )[0][0]

            # get public zone for domain
            zone_id = filter(
                lambda zone: not zone['Config']['PrivateZone'],
                filter(
                    lambda zone: zone['Name'] == (domain + '.'),
                    self.r53.list_hosted_zones()['HostedZones']
                )
            )[0]['Id']

            change_id = self.route53_create(
                zone_id,
                chall.validation_domain_name(domain),
                chall.validation(self.acme_client.key),
            )
            try:
                while True:
                    resp = self.r53.get_change(Id=change_id)
                    if resp['ChangeInfo']['Status'] == 'INSYNC':
                        break
                    time.sleep(5)

                resp = chall.response(self.acme_client.key)
                ok = resp.simple_verify(
                    chall.chall,
                    domain,
                    self.acme_client.key.public_key()
                )
                if not ok:
                    raise Exception('Not verified: ' + domain)

                self.acme_client.answer_challenge(chall, resp)

                cert_resp, _ = self.acme_client.poll_and_request_issuance(
                    acme.jose.util.ComparableX509(
                        OpenSSL.crypto.load_certificate_request(
                            OpenSSL.crypto.FILETYPE_ASN1,
                            csr.public_bytes(serialization.Encoding.DER),
                        )
                    ),
                    [authz],
                )

                pem_cert = OpenSSL.crypto.dump_certificate(
                    OpenSSL.crypto.FILETYPE_PEM,
                    cert_resp.body
                )
                pem_cert_chain = '\n'.join(
                    OpenSSL.crypto.dump_certificate(
                        OpenSSL.crypto.FILETYPE_PEM,
                        cert
                    )
                    for cert in self.acme_client.fetch_chain(cert_resp)
                )

                resp = self.iam.upload_server_certificate(
                    ServerCertificateName=next_cert_name,
                    PrivateKey=private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption(),
                    ),
                    CertificateBody=pem_cert.decode(),
                    CertificateChain=pem_cert_chain.decode(),
                    Path='/cloudfront/',
                )
                iam_cert_id_new = resp['ServerCertificateMetadata']['ServerCertificateId']

                # wait for IAM sync
                time.sleep(15)

            finally:
                self.route53_delete(
                    zone_id,
                    chall.validation_domain_name(domain),
                    chall.validation(self.acme_client.key),
                )

        if needs_cert and not iam_cert_id_new:
            raise Exception('Invariant failed, need a cert but none found')

        if not needs_cert and iam_cert_id_new:
            raise Exception('Invariant failed, dont need a cert but one found')

        if iam_cert_id_new:
            # refetch (above could take a long time)
            dist = self.cf.get_distribution(Id=cloudfront_id)
            config = dist['Distribution']['DistributionConfig']
            config['ViewerCertificate'] = {
                'IAMCertificateId': iam_cert_id_new,
                'SSLSupportMethod': 'sni-only',
                'MinimumProtocolVersion': 'TLSv1',
            }

            print 'update distribution cert: ' + iam_cert_id_new
            self.cf.update_distribution(
                DistributionConfig=config,
                Id=cloudfront_id,
                IfMatch=dist['ETag'],
            )

def main():
    parser = make_parser()
    args = parser.parse_args()

    args.domain = args.domain.decode('utf8')

    client = Client(
        boto3.client('cloudfront'),
        boto3.client('iam'),
        boto3.client('route53'),
        boto3.resource('s3'),
        args.production,
        args.s3bucket,
        args.email,
    )
    client.setup()

    client.update_cert(args.cloudfront_id, args.domain, force=args.force)

    return 0

def make_parser():
    p = argparse.ArgumentParser()

    p.add_argument('--force',
        action='store_true',
        help='force re-issue of certificate'
    )
    p.add_argument('--install',
        action='store_true',
        help='install as lambda function'
    )
    p.add_argument('--production',
        action='store_true',
        help='use production letsencrypt endpoint'
    )
    p.add_argument('s3bucket')
    p.add_argument('cloudfront_id')
    p.add_argument('email')
    p.add_argument('domain')

    return p

if __name__ == '__main__':
    sys.exit(main())
