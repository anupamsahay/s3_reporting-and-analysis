import boto3
import json
from datetime import datetime, timedelta
from botocore.exceptions import ClientError
import pandas as pd

class S3StorageAnalyzer:
    def __init__(self, profile_name=None, region='us-east-1'):
        """Initialize AWS S3 client"""
        if profile_name:
            session = boto3.Session(profile_name=profile_name)
            self.s3_client = session.client('s3', region_name=region)
        else:
            self.s3_client = boto3.client('s3', region_name=region)
        
        self.cloudwatch = boto3.client('cloudwatch', region_name=region)
        self.report_data = []
    
    def analyze_bucket_configuration(self, bucket_name):
        """Analyze individual bucket configuration"""
        bucket_info = {
            'bucket_name': bucket_name,
            'intelligent_tiering': False,
            'versioning_enabled': False,
            'encryption_type': 'None',
            'lifecycle_policies': 0,
            'unused_bucket': True,
            'creation_date': None,
            'last_modified': None,
            'total_objects': 0,
            'total_size_gb': 0
        }
        
        try:
            # Get bucket creation date
            response = self.s3_client.head_bucket(Bucket=bucket_name)
            
            # Check Intelligent Tiering
            bucket_info['intelligent_tiering'] = self.check_intelligent_tiering(bucket_name)
            
            # Check versioning
            bucket_info['versioning_enabled'] = self.check_versioning(bucket_name)
            
            # Check encryption
            bucket_info['encryption_type'] = self.check_encryption(bucket_name)
            
            # Check lifecycle policies
            bucket_info['lifecycle_policies'] = self.check_lifecycle_policies(bucket_name)
            
            # Check if bucket is unused
            bucket_info['unused_bucket'], bucket_info['last_modified'], bucket_info['total_objects'], bucket_info['total_size_gb'] = self.check_bucket_usage(bucket_name)
            
            # Get bucket creation date
            bucket_info['creation_date'] = self.get_bucket_creation_date(bucket_name)
            
        except ClientError as e:
            print(f"Error analyzing bucket {bucket_name}: {e}")
            
        return bucket_info
    
    def check_intelligent_tiering(self, bucket_name):
        """Check if Intelligent Tiering is configured"""
        try:
            response = self.s3_client.list_bucket_intelligent_tiering_configurations(
                Bucket=bucket_name
            )
            return len(response.get('IntelligentTieringConfigurationList', [])) > 0
        except ClientError:
            return False
    
    def check_versioning(self, bucket_name):
        """Check if versioning is enabled"""
        try:
            response = self.s3_client.get_bucket_versioning(Bucket=bucket_name)
            return response.get('Status') == 'Enabled'
        except ClientError:
            return False
    
    def check_encryption(self, bucket_name):
        """Check encryption configuration"""
        try:
            response = self.s3_client.get_bucket_encryption(Bucket=bucket_name)
            rules = response.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
            
            if not rules:
                return 'None'
            
            encryption_rule = rules[0].get('ApplyServerSideEncryptionByDefault', {})
            sse_algorithm = encryption_rule.get('SSEAlgorithm', '')
            
            if sse_algorithm == 'AES256':
                return 'AWS-S3 (SSE-S3)'
            elif sse_algorithm == 'aws:kms':
                kms_key = encryption_rule.get('KMSMasterKeyID', '')
                if kms_key.startswith('arn:aws:kms'):
                    return 'Customer-Managed KMS'
                else:
                    return 'AWS-Managed KMS (SSE-KMS)'
            
            return 'Unknown'
            
        except ClientError:
            return 'None'
    
    def check_lifecycle_policies(self, bucket_name):
        """Check lifecycle policies"""
        try:
            response = self.s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            return len(response.get('Rules', []))
        except ClientError:
            return 0
    
    def check_bucket_usage(self, bucket_name):
        """Check if bucket is unused based on recent activity"""
        try:
            # Get bucket objects and check last modified date
            paginator = self.s3_client.get_paginator('list_objects_v2')
            page_iterator = paginator.paginate(Bucket=bucket_name, MaxKeys=1000)
            
            total_objects = 0
            total_size = 0
            latest_modified = None
            
            for page in page_iterator:
                contents = page.get('Contents', [])
                total_objects += len(contents)
                
                for obj in contents:
                    total_size += obj['Size']
                    if latest_modified is None or obj['LastModified'] > latest_modified:
                        latest_modified = obj['LastModified']
            
            # Consider bucket unused if no objects or no activity in last 90 days
            if total_objects == 0:
                return True, None, 0, 0
            
            if latest_modified:
                days_since_activity = (datetime.now(latest_modified.tzinfo) - latest_modified).days
                is_unused = days_since_activity > 90
                return is_unused, latest_modified, total_objects, round(total_size / (1024**3), 2)
            
            return False, latest_modified, total_objects, round(total_size / (1024**3), 2)
            
        except ClientError:
            return True, None, 0, 0
    
    def get_bucket_creation_date(self, bucket_name):
        """Get bucket creation date"""
        try:
            response = self.s3_client.head_bucket(Bucket=bucket_name)
            # Unfortunately, head_bucket doesn't return creation date
            # We'll use list_buckets to get this info
            buckets_response = self.s3_client.list_buckets()
            for bucket in buckets_response['Buckets']:
                if bucket['Name'] == bucket_name:
                    return bucket['CreationDate']
            return None
        except ClientError:
            return None
    
    def create_lifecycle_policy(self, bucket_name, policy_name="OptimizedLifecyclePolicy"):
        """Create optimized lifecycle policy"""
        lifecycle_policy = {
            'Rules': [
                {
                    'ID': f'{policy_name}-StandardIA',
                    'Status': 'Enabled',
                    'Filter': {'Prefix': ''},
                    'Transitions': [
                        {
                            'Days': 30,
                            'StorageClass': 'STANDARD_IA'
                        },
                        {
                            'Days': 60,
                            'StorageClass': 'GLACIER'
                        },
                        {
                            'Days': 180,
                            'StorageClass': 'DEEP_ARCHIVE'
                        }
                    ]
                },
                {
                    'ID': f'{policy_name}-DeleteIncompleteUploads',
                    'Status': 'Enabled',
                    'Filter': {'Prefix': ''},
                    'AbortIncompleteMultipartUpload': {
                        'DaysAfterInitiation': 7
                    }
                },
                {
                    'ID': f'{policy_name}-DeleteOldVersions',
                    'Status': 'Enabled',
                    'Filter': {'Prefix': ''},
                    'NoncurrentVersionTransitions': [
                        {
                            'NoncurrentDays': 30,
                            'StorageClass': 'STANDARD_IA'
                        }
                    ],
                    'NoncurrentVersionExpiration': {
                        'NoncurrentDays': 365
                    }
                }
            ]
        }
        
        try:
            self.s3_client.put_bucket_lifecycle_configuration(
                Bucket=bucket_name,
                LifecycleConfiguration=lifecycle_policy
            )
            return True
        except ClientError as e:
            print(f"Error creating lifecycle policy for {bucket_name}: {e}")
            return False
    
    def delete_unused_bucket(self, bucket_name, force=False):
        """Delete unused bucket after confirmation"""
        if not force:
            print(f"WARNING: This will delete bucket '{bucket_name}' and all its contents!")
            confirmation = input("Type 'DELETE' to confirm: ")
            if confirmation != 'DELETE':
                print("Deletion cancelled.")
                return False
        
        try:
            # First, delete all objects in the bucket
            paginator = self.s3_client.get_paginator('list_object_versions')
            
            for page in paginator.paginate(Bucket=bucket_name):
                objects_to_delete = []
                
                # Add current versions
                for obj in page.get('Versions', []):
                    objects_to_delete.append({
                        'Key': obj['Key'],
                        'VersionId': obj['VersionId']
                    })
                
                # Add delete markers
                for obj in page.get('DeleteMarkers', []):
                    objects_to_delete.append({
                        'Key': obj['Key'],
                        'VersionId': obj['VersionId']
                    })
                
                if objects_to_delete:
                    self.s3_client.delete_objects(
                        Bucket=bucket_name,
                        Delete={'Objects': objects_to_delete}
                    )
            
            # Delete the bucket
            self.s3_client.delete_bucket(Bucket=bucket_name)
            print(f"Successfully deleted bucket: {bucket_name}")
            return True
            
        except ClientError as e:
            print(f"Error deleting bucket {bucket_name}: {e}")
            return False
    
    def generate_report(self, bucket_names=None):
        """Generate comprehensive S3 storage report"""
        if bucket_names is None:
            # Get all buckets
            response = self.s3_client.list_buckets()
            bucket_names = [bucket['Name'] for bucket in response['Buckets']]
        
        print(f"Analyzing {len(bucket_names)} buckets...")
        
        for bucket_name in bucket_names:
            print(f"Analyzing bucket: {bucket_name}")
            bucket_info = self.analyze_bucket_configuration(bucket_name)
            self.report_data.append(bucket_info)
        
        # Create DataFrame for better visualization
        df = pd.DataFrame(self.report_data)
        
        print("\n" + "="*80)
        print("AWS S3 STORAGE ANALYSIS REPORT")
        print("="*80)
        
        # Summary statistics
        total_buckets = len(df)
        intelligent_tiering_count = df['intelligent_tiering'].sum()
        versioning_enabled_count = df['versioning_enabled'].sum()
        unused_buckets_count = df['unused_bucket'].sum()
        no_lifecycle_count = (df['lifecycle_policies'] == 0).sum()
        
        print(f"\nSUMMARY:")
        print(f"Total Buckets: {total_buckets}")
        print(f"Buckets with Intelligent Tiering: {intelligent_tiering_count} ({intelligent_tiering_count/total_buckets*100:.1f}%)")
        print(f"Buckets with Versioning: {versioning_enabled_count} ({versioning_enabled_count/total_buckets*100:.1f}%)")
        print(f"Unused Buckets: {unused_buckets_count} ({unused_buckets_count/total_buckets*100:.1f}%)")
        print(f"Buckets without Lifecycle Policies: {no_lifecycle_count} ({no_lifecycle_count/total_buckets*100:.1f}%)")
        
        # Encryption breakdown
        print(f"\nENCRYPTION BREAKDOWN:")
        encryption_counts = df['encryption_type'].value_counts()
        for enc_type, count in encryption_counts.items():
            print(f"  {enc_type}: {count} buckets ({count/total_buckets*100:.1f}%)")
        
        # Detailed bucket information
        print(f"\nDETAILED BUCKET ANALYSIS:")
        print("-" * 80)
        
        for _, row in df.iterrows():
            print(f"\nBucket: {row['bucket_name']}")
            print(f"  Intelligent Tiering: {'✓' if row['intelligent_tiering'] else '✗'}")
            print(f"  Versioning: {'✓' if row['versioning_enabled'] else '✗'}")
            print(f"  Encryption: {row['encryption_type']}")
            print(f"  Lifecycle Policies: {row['lifecycle_policies']}")
            print(f"  Total Objects: {row['total_objects']:,}")
            print(f"  Total Size: {row['total_size_gb']} GB")
            print(f"  Last Activity: {row['last_modified'] if row['last_modified'] else 'No objects'}")
            print(f"  Status: {'UNUSED' if row['unused_bucket'] else 'ACTIVE'}")
        
        # Recommendations
        print(f"\n" + "="*80)
        print("RECOMMENDATIONS:")
        print("="*80)
        
        if no_lifecycle_count > 0:
            print(f"• {no_lifecycle_count} buckets need lifecycle policies for cost optimization")
        
        if total_buckets - intelligent_tiering_count > 0:
            print(f"• {total_buckets - intelligent_tiering_count} buckets could benefit from Intelligent Tiering")
        
        if unused_buckets_count > 0:
            print(f"• {unused_buckets_count} unused buckets can be deleted to save costs")
        
        unencrypted_count = (df['encryption_type'] == 'None').sum()
        if unencrypted_count > 0:
            print(f"• {unencrypted_count} buckets need encryption enabled")
        
        return df
    
    def apply_optimizations(self, bucket_names=None, delete_unused=False):
        """Apply recommended optimizations"""
        if bucket_names is None:
            bucket_names = [data['bucket_name'] for data in self.report_data]
        
        for bucket_data in self.report_data:
            bucket_name = bucket_data['bucket_name']
            
            if bucket_name not in bucket_names:
                continue
                
            print(f"\nOptimizing bucket: {bucket_name}")
            
            # Apply lifecycle policy if none exists
            if bucket_data['lifecycle_policies'] == 0 and not bucket_data['unused_bucket']:
                print(f"  Creating lifecycle policy...")
                if self.create_lifecycle_policy(bucket_name):
                    print(f"  ✓ Lifecycle policy created")
                else:
                    print(f"  ✗ Failed to create lifecycle policy")
            
            # Delete unused buckets if requested
            if bucket_data['unused_bucket'] and delete_unused:
                print(f"  Deleting unused bucket...")
                if self.delete_unused_bucket(bucket_name, force=True):
                    print(f"  ✓ Bucket deleted")
                else:
                    print(f"  ✗ Failed to delete bucket")

# Usage Example
if __name__ == "__main__":
    # Initialize the analyzer
    analyzer = S3StorageAnalyzer(profile_name=None)  # Use default AWS credentials
    
    # Generate comprehensive report
    df = analyzer.generate_report()
    
    # Save report to CSV
    df.to_csv('s3_storage_report.csv', index=False)
    print(f"\nReport saved to: s3_storage_report.csv")
    
    # Apply optimizations (uncomment to execute)
    # analyzer.apply_optimizations(delete_unused=True)  # Set to True to delete unused buckets
