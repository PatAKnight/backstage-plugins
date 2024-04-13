/**
 * TODO: Test to see if it works correctly
 * * Add permission policy
 * * Remove permission policy
 * * Add and Remove permission policies
 * * Edit permission policy - this should be treated as add and remove but double check
 * * Add group policy - Two tests, with existing role and without existing role
 * * Remove group policy - Two tests, with second existing role and with only one existing role
 * * Add and Remove group policy - Four tests, should be similar to the other two
 * * Edit group policy - should be treated as add and remove but double check
 *
 * TODO: see how performant it is with the above tests
 * * Do the 924 permissions and 924 roles while testing
 * * Make sure that you add the group policies of the roles that you want pre-existing to make sure that it is prepped for testing
 *
 * TODO: we may or may not need a flag to whenever we are loading updated permissions
 * * this flag would be picked up by the handle function to determine if it needs to wait for the completion of the file watcher
 * * same with the rest api to ensure that there is no overlap between the two
 */
import { FileAdapter, newEnforcer, newModelFromString } from 'casbin';
import chokidar from 'chokidar';
import { parse } from 'csv-parse/sync';
import { difference } from 'lodash';
import { Logger } from 'winston';

import fs from 'fs';

import { RoleMetadataStorage } from '../database/role-metadata';
import {
  metadataStringToPolicy,
  policyToString,
  transformArrayToPolicy,
} from '../helper';
import { EnforcerDelegate } from '../service/enforcer-delegate';
import { MODEL } from '../service/permission-model';
import {
  validateGroupingPolicy,
  validatePolicy,
} from '../service/policies-validation';
import { CSV_PERMISSION_POLICY_FILE_AUTHOR } from './csv';

type CSVFilePolicies = {
  addedPolicies: string[][];
  addedGroupPolicies: string[][];
  removedPolicies: string[][];
  removedGroupPolicies: string[][];
};

export class CSVFileWatcher {
  private currentContent: string[][];
  private csvFilePolicies: CSVFilePolicies;
  private csvFileName: string;
  constructor(
    private readonly enforcer: EnforcerDelegate,
    private readonly logger: Logger,
    private readonly roleMetadataStorage: RoleMetadataStorage,
  ) {
    this.csvFileName = '';
    this.currentContent = [];
    this.csvFilePolicies = {
      addedPolicies: [],
      addedGroupPolicies: [],
      removedPolicies: [],
      removedGroupPolicies: [],
    };
  }

  getCurrentContents(): string {
    return fs.readFileSync(this.csvFileName, 'utf-8');
  }

  parse(): string[][] {
    const content = this.getCurrentContents();
    const parser = parse(content, {
      skip_empty_lines: true,
      relax_column_count: true,
      trim: true,
    });

    return parser;
  }

  watchFile(): void {
    const watcher = chokidar.watch(this.csvFileName);
    watcher.on('change', async path => {
      this.logger.info(`file ${path} has changed`);
      await this.onChange();
    });
  }

  async initialize(csvFileName: string): Promise<void> {
    const start = new Date().getTime();
    this.csvFileName = csvFileName;
    const content = this.parse();
    const tempEnforcer = await newEnforcer(
      newModelFromString(MODEL),
      new FileAdapter(this.csvFileName),
    );

    // Working on delete first
    const policiesToRemove =
      await this.enforcer.getFilteredPolicyMetadata('csv-file');

    for (const policy of policiesToRemove) {
      const convertedPolicy = metadataStringToPolicy(policy.policy);
      if (
        convertedPolicy.length === 2 &&
        !(await tempEnforcer.hasGroupingPolicy(...convertedPolicy))
      ) {
        this.csvFilePolicies.removedGroupPolicies.push(convertedPolicy);
      } else if (
        convertedPolicy.length > 2 &&
        !(await tempEnforcer.hasPolicy(...convertedPolicy))
      ) {
        this.csvFilePolicies.removedPolicies.push(convertedPolicy);
      }
    }

    // Working on add next
    const policiesToAdd = await tempEnforcer.getPolicy();
    const groupPoliciesToAdd = await tempEnforcer.getGroupingPolicy();
    for (const policy of policiesToAdd) {
      if (!(await this.enforcer.hasPolicy(...policy))) {
        this.csvFilePolicies.addedPolicies.push(policy);
      }
    }
    for (const groupPolicy of groupPoliciesToAdd) {
      if (!(await this.enforcer.hasGroupingPolicy(...groupPolicy))) {
        this.csvFilePolicies.addedGroupPolicies.push(groupPolicy);
      }
    }

    // We pass current here because this is during initialization and it has not changed yet
    this.updatePolicies(content);
    const end = new Date().getTime();
    console.log(`it took ${end - start} ms to complete initialize`);
  }

  async onChange(): Promise<void> {
    const start = new Date().getTime();
    const newContent = this.parse();
    const currentFlatContent = this.currentContent.flatMap(data => {
      return policyToString(data);
    });
    const newFlatContent = newContent.flatMap(data => {
      return policyToString(data);
    });

    const diffRemoved = difference(currentFlatContent, newFlatContent); // policy was removed
    const diffAdded = difference(newFlatContent, currentFlatContent); // policy was added

    if (diffRemoved.length === 0 && diffAdded.length === 0) {
      return;
    }

    diffRemoved.forEach(policy => {
      const convertedPolicy = metadataStringToPolicy(policy);
      if (convertedPolicy[0] === 'p') {
        convertedPolicy.splice(0, 1);
        this.csvFilePolicies.removedPolicies.push(convertedPolicy);
      } else if (convertedPolicy[0] === 'g') {
        convertedPolicy.splice(0, 1);
        this.csvFilePolicies.removedGroupPolicies.push(convertedPolicy);
      }
    });

    diffAdded.forEach(policy => {
      const convertedPolicy = metadataStringToPolicy(policy);
      if (convertedPolicy[0] === 'p') {
        convertedPolicy.splice(0, 1);
        this.csvFilePolicies.addedPolicies.push(convertedPolicy);
      } else if (convertedPolicy[0] === 'g') {
        convertedPolicy.splice(0, 1);
        this.csvFilePolicies.addedGroupPolicies.push(convertedPolicy);
      }
    });

    await this.updatePolicies(newContent);
    const end = new Date().getTime();
    console.log(`it took ${end - start} ms to complete on change`);
  }

  async updatePolicies(newContent: string[][]): Promise<void> {
    this.currentContent = newContent;

    if (this.csvFilePolicies.addedPolicies.length > 0)
      await this.addPermissionPolicies();
    if (this.csvFilePolicies.removedPolicies.length > 0)
      await this.removePermissionPolicies();
    if (this.csvFilePolicies.addedGroupPolicies.length > 0)
      await this.addRoles();
    if (this.csvFilePolicies.removedGroupPolicies.length > 0)
      await this.removeRoles();
  }

  async addPermissionPolicies(): Promise<void> {
    for (const policy of this.csvFilePolicies.addedPolicies) {
      const err = validatePolicy(transformArrayToPolicy(policy));
      if (err) {
        this.logger.warn(
          `Failed to validate policy from file ${this.csvFileName}. Cause: ${err.message}`,
        );
        continue;
      }
      await this.enforcer.addPolicy(policy, 'csv-file');
    }

    this.csvFilePolicies.addedPolicies = [];
  }

  async removePermissionPolicies(): Promise<void> {
    for (const policy of this.csvFilePolicies.removedPolicies) {
      const err = validatePolicy(transformArrayToPolicy(policy));
      if (err) {
        this.logger.warn(
          `Failed to validate policy from file ${this.csvFileName}. Cause: ${err.message}`,
        );
        continue;
      }
      await this.enforcer.removePolicy(policy, 'csv-file', true);
    }
    this.csvFilePolicies.removedPolicies = [];
  }

  // Split this
  async addRoles(): Promise<void> {
    for (const groupPolicy of this.csvFilePolicies.addedGroupPolicies) {
      const err = await validateGroupingPolicy(
        groupPolicy,
        this.csvFileName,
        this.roleMetadataStorage,
        'csv-file',
      );
      if (err) {
        this.logger.warn(
          `Failed to validate policy from file ${this.csvFileName}. Cause: ${err.message}`,
        );
        continue;
      }
      await this.enforcer.addGroupingPolicy(groupPolicy, {
        source: 'csv-file',
        roleEntityRef: groupPolicy[1],
        author: CSV_PERMISSION_POLICY_FILE_AUTHOR,
        modifiedBy: CSV_PERMISSION_POLICY_FILE_AUTHOR,
      });
    }
    this.csvFilePolicies.addedGroupPolicies = [];
  }

  async removeRoles(): Promise<void> {
    for (const groupPolicy of this.csvFilePolicies.removedGroupPolicies) {
      // this requires knowledge of whether or not it is an update
      const isUpdate = await this.enforcer.getFilteredGroupingPolicy(
        1,
        groupPolicy[1],
      );

      await this.enforcer.removeGroupingPolicy(
        groupPolicy,
        {
          source: 'csv-file',
          roleEntityRef: groupPolicy[1],
          author: CSV_PERMISSION_POLICY_FILE_AUTHOR,
          modifiedBy: CSV_PERMISSION_POLICY_FILE_AUTHOR,
        },
        isUpdate.length > 1,
        true,
      );
    }
    this.csvFilePolicies.removedGroupPolicies = [];
  }
}
