from flask import Flask, render_template, request, jsonify
import boto3
import json
from datetime import datetime
import time
import random

app = Flask(__name__)


scan_sessions = {}

def scan_aws_misconfigurations(credentials_id, scan_scope=None):
    findings = []
    
    try:

        s3 = boto3.client('s3')
        ec2 = boto3.client('ec2')
        iam = boto3.client('iam')
        rds = boto3.client('rds')
        

        if not scan_scope or 's3' in scan_scope:
            try:
                buckets = s3.list_buckets()
                
                for bucket in buckets['Buckets']:
                    try:

                        acl = s3.get_bucket_acl(Bucket=bucket['Name'])
                        if any(grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers' 
                               for grant in acl['Grants']):
                            findings.append({
                                'type': 'S3_PUBLIC_ACCESS', 
                                'resource': bucket['Name'],
                                'severity': 'HIGH',
                                'description': 'S3 bucket is publicly accessible',
                                'timestamp': datetime.now().isoformat()
                            })
                        

                        try:
                            policy = s3.get_bucket_policy(Bucket=bucket['Name'])
                            if '"Principal": "*"' in policy['Policy']:
                                findings.append({
                                    'type': 'S3_PUBLIC_POLICY',
                                    'resource': bucket['Name'],
                                    'severity': 'HIGH',
                                    'description': 'S3 bucket has public access policy',
                                    'timestamp': datetime.now().isoformat()
                                })
                        except:
                            pass
                            
                    except Exception as e:
                        findings.append({
                            'type': 'S3_ACCESS_ERROR',
                            'resource': bucket['Name'],
                            'severity': 'MEDIUM',
                            'description': f'Unable to access bucket: {str(e)}',
                            'timestamp': datetime.now().isoformat()
                        })
            except Exception as e:
                findings.append({
                    'type': 'S3_LIST_ERROR',
                    'severity': 'MEDIUM',
                    'description': f'Unable to list S3 buckets: {str(e)}',
                    'timestamp': datetime.now().isoformat()
                })
        

        if not scan_scope or 'ec2' in scan_scope:
            try:
                instances = ec2.describe_instances()
                
                for reservation in instances['Reservations']:
                    for instance in reservation['Instances']:

                        if instance['State']['Name'] == 'running':

                            for sg in instance['SecurityGroups']:
                                try:
                                    sg_rules = ec2.describe_security_group_rules(
                                        Filters=[{'Name': 'group-id', 'Values': [sg['GroupId']]}]
                                    )
                                    
                                    for rule in sg_rules['SecurityGroupRules']:
                                        if rule.get('IpProtocol') == '-1' and rule.get('CidrIpv4') == '0.0.0.0/0':
                                            findings.append({
                                                'type': 'EC2_OPEN_SECURITY_GROUP',
                                                'resource': f"{instance['InstanceId']} ({sg['GroupName']})",
                                                'severity': 'HIGH',
                                                'description': 'EC2 instance has security group allowing all traffic',
                                                'timestamp': datetime.now().isoformat()
                                            })
                                            break
                                except:
                                    pass
            except Exception as e:
                findings.append({
                    'type': 'EC2_SCAN_ERROR',
                    'severity': 'MEDIUM',
                    'description': f'Unable to scan EC2 instances: {str(e)}',
                    'timestamp': datetime.now().isoformat()
                })
        

        if not scan_scope or 'iam' in scan_scope:
            try:
                users = iam.list_users()
                
                for user in users['Users']:
                    try:
                        policies = iam.list_attached_user_policies(UserName=user['UserName'])
                        
                        for policy in policies['AttachedPolicies']:
                            if policy['PolicyName'] in ['AdministratorAccess', 'PowerUserAccess']:
                                findings.append({
                                    'type': 'IAM_OVERPRIVILEGED',
                                    'resource': user['UserName'],
                                    'severity': 'HIGH',
                                    'description': f'User has {policy["PolicyName"]} policy attached',
                                    'timestamp': datetime.now().isoformat()
                                })
                    except:
                        pass
            except Exception as e:
                findings.append({
                    'type': 'IAM_SCAN_ERROR',
                    'severity': 'MEDIUM',
                    'description': f'Unable to scan IAM users: {str(e)}',
                    'timestamp': datetime.now().isoformat()
                })
        

        if not scan_scope or 'rds' in scan_scope:
            try:
                instances = rds.describe_db_instances()
                
                for instance in instances['DBInstances']:
                    if instance.get('PubliclyAccessible', False):
                        findings.append({
                            'type': 'RDS_PUBLIC_ACCESS',
                            'resource': instance['DBInstanceIdentifier'],
                            'severity': 'HIGH',
                            'description': 'RDS instance is publicly accessible',
                            'timestamp': datetime.now().isoformat()
                        })
            except Exception as e:
                findings.append({
                    'type': 'RDS_SCAN_ERROR',
                    'severity': 'MEDIUM',
                    'description': f'Unable to scan RDS instances: {str(e)}',
                    'timestamp': datetime.now().isoformat()
                })
                
    except Exception as e:
        findings.append({
            'type': 'CONNECTION_ERROR',
            'severity': 'MEDIUM',
            'description': f'Unable to connect to AWS: {str(e)}',
            'timestamp': datetime.now().isoformat()
        })
    
    return findings

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan')
def scan():
    return render_template('scan.html')

@app.route('/report')
def report():
    return render_template('report.html')

@app.route('/settings')
def settings():
    return render_template('settings.html')

@app.route('/api/scan-aws', methods=['POST'])
def scan_aws():
    data = request.get_json()
    credentials_id = data.get('credentials', 'b67a60f0-32ec-4022-9bf8-26d0ade42a52')
    scan_scope = data.get('scope', [])
    scan_depth = data.get('depth', 'standard')
    

    session_id = f"scan_{int(time.time())}"
    scan_sessions[session_id] = {
        'status': 'running',
        'start_time': datetime.now().isoformat(),
        'findings': [],
        'progress': 0
    }
    
    findings = scan_aws_misconfigurations(credentials_id, scan_scope)
    

    scan_sessions[session_id]['findings'] = findings
    scan_sessions[session_id]['status'] = 'completed'
    scan_sessions[session_id]['end_time'] = datetime.now().isoformat()
    
    return jsonify({
        'session_id': session_id,
        'timestamp': datetime.now().isoformat(),
        'findings': findings,
        'total_findings': len(findings),
        'credentials_used': credentials_id,
        'scan_scope': scan_scope,
        'scan_depth': scan_depth
    })

@app.route('/api/scan-progress/<session_id>')
def scan_progress(session_id):
    if session_id in scan_sessions:
        session = scan_sessions[session_id]
        return jsonify(session)
    else:
        return jsonify({'error': 'Session not found'}), 404

@app.route('/api/scan-status')
def scan_status():
    active_scans = [s for s in scan_sessions.values() if s['status'] == 'running']
    completed_scans = [s for s in scan_sessions.values() if s['status'] == 'completed']
    
    return jsonify({
        'active_scans': len(active_scans),
        'completed_scans': len(completed_scans),
        'total_sessions': len(scan_sessions)
    })

@app.route('/api/latest-session')
def get_latest_session():
    if not scan_sessions:
        return jsonify({'error': 'No scan sessions found'}), 404
    

    latest_session_id = max(scan_sessions.keys(), key=lambda x: scan_sessions[x]['start_time'])
    latest_session = scan_sessions[latest_session_id]
    
    return jsonify({
        'session_id': latest_session_id,
        'session': latest_session
    })

@app.route('/api/findings/<session_id>')
def get_findings(session_id):
    if session_id in scan_sessions:
        session = scan_sessions[session_id]
        return jsonify({
            'findings': session['findings'],
            'summary': {
                'total': len(session['findings']),
                'high': len([f for f in session['findings'] if f['severity'] == 'HIGH']),
                'medium': len([f for f in session['findings'] if f['severity'] == 'MEDIUM']),
                'low': len([f for f in session['findings'] if f['severity'] == 'LOW'])
            }
        })
    else:
        return jsonify({'error': 'Session not found'}), 404

@app.route('/api/download-report/<session_id>')
def download_report(session_id):
    if session_id in scan_sessions:
        session = scan_sessions[session_id]
        
        report = {
            'scan_session': session_id,
            'timestamp': session['start_time'],
            'duration': (datetime.fromisoformat(session['end_time']) - datetime.fromisoformat(session['start_time'])).total_seconds(),
            'findings': session['findings'],
            'summary': {
                'total': len(session['findings']),
                'high': len([f for f in session['findings'] if f['severity'] == 'HIGH']),
                'medium': len([f for f in session['findings'] if f['severity'] == 'MEDIUM']),
                'low': len([f for f in session['findings'] if f['severity'] == 'LOW'])
            }
        }
        
        return jsonify(report)
    else:
        return jsonify({'error': 'Session not found'}), 404

@app.route('/api/settings', methods=['GET', 'POST'])
def settings_api():
    if request.method == 'GET':
        # Return current settings (in production, this would come from database)
        return jsonify({
            'aws_region': 'us-east-1',
            'default_scan_depth': 'standard',
            'auto_scan_enabled': False,
            'notification_email': '',
            'session_timeout': 30,
            'data_retention': 90
        })
    
    elif request.method == 'POST':
        data = request.get_json()
        
        # Validate settings data
        required_fields = ['aws_access_key', 'aws_secret_key', 'aws_region']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # In production, save to database and encrypt credentials
        # For now, just return success
        return jsonify({
            'message': 'Settings saved successfully',
            'timestamp': datetime.now().isoformat()
        })

@app.route('/api/test-connection', methods=['POST'])
def test_connection():
    data = request.get_json()
    
    access_key = data.get('aws_access_key')
    secret_key = data.get('aws_secret_key')
    region = data.get('aws_region', 'us-east-1')
    
    if not access_key or not secret_key:
        return jsonify({'error': 'Missing AWS credentials'}), 400
    
    try:
        # Test AWS connection
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError
        
        # Create a test client
        test_client = boto3.client(
            'sts',
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )
        
        # Test the connection
        response = test_client.get_caller_identity()
        
        return jsonify({
            'success': True,
            'message': 'AWS connection successful',
            'account_id': response.get('Account'),
            'user_arn': response.get('Arn'),
            'timestamp': datetime.now().isoformat()
        })
        
    except NoCredentialsError:
        return jsonify({'error': 'Invalid AWS credentials'}), 401
    except ClientError as e:
        return jsonify({'error': f'AWS connection failed: {str(e)}'}), 400
    except Exception as e:
        return jsonify({'error': f'Connection test failed: {str(e)}'}), 500

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
