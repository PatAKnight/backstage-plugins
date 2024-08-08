import { BackstageUserInfo } from '@backstage/backend-plugin-api';
import {
  AuthorizeResult,
  ConditionalPolicyDecision,
  isResourcePermission,
  Permission,
  PermissionCondition,
  PermissionCriteria,
  PermissionRuleParams,
  PolicyDecision,
  ResourcePermission,
} from '@backstage/plugin-permission-common';
import {
  PermissionPolicy,
  PolicyQuery,
  PolicyQueryUser,
} from '@backstage/plugin-permission-node';

import { AuditLogger } from '@janus-idp/backstage-plugin-audit-log-node';
import {
  NonEmptyArray,
  toPermissionAction,
} from '@janus-idp/backstage-plugin-rbac-common';

import {
  createPermissionEvaluationOptions,
  EVALUATE_PERMISSION_ACCESS_STAGE,
  EvaluationEvents,
} from '../audit-log/audit-logger';
import { replaceAliases } from '../conditional-aliases/alias-resolver';
import { ConditionalStorage } from '../database/conditional-storage';
import { EnforcerDelegate } from '../service/enforcer-delegate';

export const ADMIN_ROLE_NAME = 'role:default/rbac_admin';
export const ADMIN_ROLE_AUTHOR = 'application configuration';

const evaluatePermMsg = (
  userEntityRef: string | undefined,
  result: AuthorizeResult,
  permission: Permission,
) =>
  `${userEntityRef} is ${result} for permission '${permission.name}'${
    isResourcePermission(permission)
      ? `, resource type '${permission.resourceType}'`
      : ''
  } and action '${toPermissionAction(permission.attributes)}'`;

export class RBACPermissionPolicy implements PermissionPolicy {
  private readonly superUserList?: string[];

  constructor(
    private readonly enforcer: EnforcerDelegate,
    private readonly auditLogger: AuditLogger,
    private readonly conditionStorage: ConditionalStorage,
    superUserList?: string[],
  ) {
    this.superUserList = superUserList;
  }

  async handle(
    request: PolicyQuery,
    user?: PolicyQueryUser,
  ): Promise<PolicyDecision> {
    const userEntityRef = user?.info.userEntityRef ?? `user without entity`;

    let auditOptions = createPermissionEvaluationOptions(
      `Policy check for ${userEntityRef}`,
      userEntityRef,
      request,
    );
    this.auditLogger.auditLog(auditOptions);

    try {
      let status = false;

      const action = toPermissionAction(request.permission.attributes);
      if (!user) {
        const msg = evaluatePermMsg(
          userEntityRef,
          AuthorizeResult.DENY,
          request.permission,
        );
        auditOptions = createPermissionEvaluationOptions(
          msg,
          userEntityRef,
          request,
          { result: AuthorizeResult.DENY },
        );
        await this.auditLogger.auditLog(auditOptions);
        return { result: AuthorizeResult.DENY };
      }

      const permissionName = request.permission.name;
      const roles = await this.enforcer.getRolesForUser(userEntityRef);

      if (isResourcePermission(request.permission)) {
        const resourceType = request.permission.resourceType;

        // handle conditions if they are present
        if (user) {
          const conditionResult = await this.handleConditions(
            userEntityRef,
            request,
            roles,
            user.info,
          );
          if (conditionResult) {
            return conditionResult;
          }
        }

        // handle permission with 'resource' type
        const hasNamedPermission =
          await this.hasImplicitPermissionSpecifiedByName(
            userEntityRef,
            permissionName,
            action,
          );
        // Let's set up higher priority for permission specified by name, than by resource type
        const obj = hasNamedPermission ? permissionName : resourceType;

        status = await this.isAuthorized(userEntityRef, obj, action, roles);
      } else {
        // handle permission with 'basic' type
        status = await this.isAuthorized(
          userEntityRef,
          permissionName,
          action,
          roles,
        );
      }

      const result = status ? AuthorizeResult.ALLOW : AuthorizeResult.DENY;

      const msg = evaluatePermMsg(userEntityRef, result, request.permission);
      auditOptions = createPermissionEvaluationOptions(
        msg,
        userEntityRef,
        request,
        { result },
      );
      await this.auditLogger.auditLog(auditOptions);
      return { result };
    } catch (error) {
      await this.auditLogger.auditLog({
        message: 'Permission policy check failed',
        eventName: EvaluationEvents.PERMISSION_EVALUATION_FAILED,
        stage: EVALUATE_PERMISSION_ACCESS_STAGE,
        status: 'failed',
        errors: [error],
      });
      return { result: AuthorizeResult.DENY };
    }
  }

  private async hasImplicitPermissionSpecifiedByName(
    userEntityRef: string,
    permissionName: string,
    action: string,
  ): Promise<boolean> {
    const userPerms =
      await this.enforcer.getImplicitPermissionsForUser(userEntityRef);
    for (const perm of userPerms) {
      if (permissionName === perm[1] && action === perm[2]) {
        return true;
      }
    }
    return false;
  }

  private isAuthorized = async (
    userIdentity: string,
    permission: string,
    action: string,
    roles: string[],
  ): Promise<boolean> => {
    if (this.superUserList!.includes(userIdentity)) {
      return true;
    }

    return await this.enforcer.enforce(userIdentity, permission, action, roles);
  };

  private async handleConditions(
    userEntityRef: string,
    request: PolicyQuery,
    roles: string[],
    userInfo: BackstageUserInfo,
  ): Promise<PolicyDecision | undefined> {
    const permissionName = request.permission.name;
    const resourceType = (request.permission as ResourcePermission)
      .resourceType;
    const action = toPermissionAction(request.permission.attributes);

    const conditions: PermissionCriteria<
      PermissionCondition<string, PermissionRuleParams>
    >[] = [];
    let pluginId = '';
    for (const role of roles) {
      const conditionalDecisions = await this.conditionStorage.filterConditions(
        role,
        undefined,
        resourceType,
        [action],
        [permissionName],
      );

      if (conditionalDecisions.length === 1) {
        pluginId = conditionalDecisions[0].pluginId;
        conditions.push(conditionalDecisions[0].conditions);
      }

      // this error is unexpected and should not happen, but just in case handle it.
      if (conditionalDecisions.length > 1) {
        const msg = `Detected ${JSON.stringify(
          conditionalDecisions,
        )} collisions for conditional policies. Expected to find a stored single condition for permission with name ${permissionName}, resource type ${resourceType}, action ${action} for user ${userEntityRef}`;
        const auditOptions = createPermissionEvaluationOptions(
          msg,
          userEntityRef,
          request,
          { result: AuthorizeResult.DENY },
        );
        await this.auditLogger.auditLog(auditOptions);
        return {
          result: AuthorizeResult.DENY,
        };
      }
    }

    if (conditions.length > 0) {
      const result: ConditionalPolicyDecision = {
        pluginId,
        result: AuthorizeResult.CONDITIONAL,
        resourceType,
        conditions: {
          anyOf: conditions as NonEmptyArray<
            PermissionCriteria<
              PermissionCondition<string, PermissionRuleParams>
            >
          >,
        },
      };

      replaceAliases(result.conditions, userInfo);

      const msg = `Send condition to plugin with id ${pluginId} to evaluate permission ${permissionName} with resource type ${resourceType} and action ${action} for user ${userEntityRef}`;
      const auditOptions = createPermissionEvaluationOptions(
        msg,
        userEntityRef,
        request,
        result,
      );
      await this.auditLogger.auditLog(auditOptions);
      return result;
    }
    return undefined;
  }
}
