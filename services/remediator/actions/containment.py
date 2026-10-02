"""
CloudSecOps Sentinel - SOAR Containment Actions
Automated rollback, isolation, and remediation procedures for GCP resources.
"""

import logging
from typing import Dict, Any

logger = logging.getLogger("soar-containment")

def revoke_service_account_key(resource_name: str, dry_run: bool = False) -> Dict[str, Any]:
    """
    T1098.001 Containment:
    Deletes or disables a rogue Service Account Key.
    Resource format: projects/{project}/serviceAccounts/{email}/keys/{key_id}
    """
    logger.warning(f"Initiating revocation for key: {resource_name}")
    if dry_run:
        return {"status": "SUCCESS", "action": "REVOKE_KEY", "resource": resource_name, "mode": "DRY_RUN"}

    try:
        from googleapiclient import discovery
        # Parse resource name
        parts = resource_name.split("/")
        if "keys" in parts:
            key_id = parts[parts.index("keys") + 1]
            sa_email = parts[parts.index("serviceAccounts") + 1]
            project = parts[parts.index("projects") + 1]
            
            service = discovery.build('iam', 'v1')
            full_key_name = f"projects/{project}/serviceAccounts/{sa_email}/keys/{key_id}"
            service.projects().serviceAccounts().keys().delete(name=full_key_name).execute()
            logger.info(f"Successfully deleted rogue service account key: {full_key_name}")
            return {"status": "SUCCESS", "action": "DELETED_KEY", "key": full_key_name}
        else:
            return {"status": "SKIPPED", "reason": "Malformed key resource format", "resource": resource_name}
    except Exception as e:
        logger.error(f"Failed to delete service account key: {e}")
        return {"status": "ERROR", "error": str(e), "resource": resource_name}


def enforce_public_access_prevention(resource_name: str, dry_run: bool = False) -> Dict[str, Any]:
    """
    T1530 Containment:
    Enforces 'enforced' Public Access Prevention and strips 'allUsers' / 'allAuthenticatedUsers'
    from bucket IAM policy.
    """
    bucket_name = resource_name.replace("projects/_/buckets/", "").replace("buckets/", "").strip()
    logger.warning(f"Enforcing Public Access Prevention on bucket: {bucket_name}")

    if dry_run:
        return {"status": "SUCCESS", "action": "LOCK_BUCKET", "bucket": bucket_name, "mode": "DRY_RUN"}

    try:
        from google.cloud import storage
        client = storage.Client()
        bucket = client.get_bucket(bucket_name)

        # 1. Enforce Public Access Prevention
        bucket.iam_configuration.public_access_prevention = "enforced"
        bucket.patch()
        logger.info(f"Set public_access_prevention = enforced on bucket: {bucket_name}")

        # 2. Strip allUsers and allAuthenticatedUsers from IAM
        policy = bucket.get_iam_policy(requested_policy_version=3)
        for binding in policy.bindings:
            members = binding.get("members", set())
            sanitized = {m for m in members if m not in ["allUsers", "allAuthenticatedUsers"]}
            binding["members"] = sanitized

        bucket.set_iam_policy(policy)
        logger.info(f"Stripped public members from IAM policy on bucket: {bucket_name}")

        return {"status": "SUCCESS", "action": "ENFORCED_PAP_AND_STRIPPED_PUBLIC_IAM", "bucket": bucket_name}
    except Exception as e:
        logger.error(f"Failed to enforce bucket public access prevention: {e}")
        return {"status": "ERROR", "error": str(e), "bucket": bucket_name}


def rollback_iam_grant(project_id: str, principal_email: str, resource_name: str, dry_run: bool = False) -> Dict[str, Any]:
    """
    T1078.004 Containment:
    Removes critical admin roles (owner/editor) granted to an unauthorized principal.
    """
    logger.warning(f"Rolling back unauthorized IAM roles for principal: {principal_email} on {resource_name}")

    if dry_run:
        return {"status": "SUCCESS", "action": "REVOKE_IAM_ROLE", "principal": principal_email, "mode": "DRY_RUN"}

    try:
        from google.cloud import resourcemanager_v3
        client = resourcemanager_v3.ProjectsClient()
        project_resource = f"projects/{project_id}"

        policy = client.get_iam_policy(resource=project_resource)
        modified = False

        dangerous_roles = {"roles/owner", "roles/editor", "roles/resourcemanager.organizationAdmin"}
        member_str = f"user:{principal_email}" if not principal_email.startswith("serviceAccount:") else principal_email

        for binding in policy.bindings:
            if binding.role in dangerous_roles and member_str in binding.members:
                binding.members.remove(member_str)
                modified = True
                logger.info(f"Removed '{member_str}' from role '{binding.role}'")

        if modified:
            client.set_iam_policy(resource=project_resource, policy=policy)
            return {"status": "SUCCESS", "action": "REVOKED_PRIVILEGED_ROLE", "principal": principal_email}
        else:
            return {"status": "NOOP", "message": "No privileged bindings found for principal"}

    except Exception as e:
        logger.error(f"Failed to rollback IAM grant: {e}")
        return {"status": "ERROR", "error": str(e)}
