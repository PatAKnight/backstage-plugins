import { TokenManager } from '@backstage/backend-common';
import { CatalogApi } from '@backstage/catalog-client';
import { Entity } from '@backstage/catalog-model';

import { alg, Graph } from '@dagrejs/graphlib';
import { Knex } from 'knex';
import { Logger } from 'winston';

interface Relation {
  source_entity_ref: string;
  target_entity_ref: string;
}

// AncestorSearchMemo - should be used to build group hierarchy graph for User entity reference.
// It supports search group entity reference link in the graph.
// Also AncestorSearchMemo supports detection cycle dependencies between groups in the graph.
//
export class AncestorSearchMemo {
  private graph: Graph;

  private tokenManager: TokenManager;
  private catalogApi: CatalogApi;
  private catalogClient: Knex;

  private userEntityRef: string;

  private allGroups: Entity[];
  private allRelations: Relation[];

  constructor(
    userEntityRef: string,
    tokenManager: TokenManager,
    catalogApi: CatalogApi,
    catalogClient: Knex,
  ) {
    this.graph = new Graph({ directed: true });
    this.userEntityRef = userEntityRef;
    this.tokenManager = tokenManager;
    this.catalogApi = catalogApi;
    this.catalogClient = catalogClient;
    this.allGroups = [];
    this.allRelations = [];
  }

  isAcyclic(): boolean {
    return alg.isAcyclic(this.graph);
  }

  findCycles(): string[][] {
    return alg.findCycles(this.graph);
  }

  setEdge(parentEntityRef: string, childEntityRef: string) {
    this.graph.setEdge(parentEntityRef, childEntityRef);
  }

  setNode(entityRef: string): void {
    this.graph.setNode(entityRef);
  }

  hasEntityRef(groupRef: string): boolean {
    return this.graph.hasNode(groupRef);
  }

  debugNodesAndEdges(log: Logger, userEntity: string): void {
    log.debug(
      `SubGraph edges: ${JSON.stringify(this.graph.edges())} for ${userEntity}`,
    );
    log.debug(
      `SubGraph nodes: ${JSON.stringify(this.graph.nodes())} for ${userEntity}`,
    );
  }

  getNodes(): string[] {
    return this.graph.nodes();
  }

  async getAllRelations(): Promise<Relation[]> {
    try {
      const rows = await this.catalogClient('relations')
        .select('source_entity_ref', 'target_entity_ref')
        .where('type', 'childOf')
        .then();
      return rows;
    } catch (error) {
      console.log(`error ${error}`);
      return [];
    }
  }

  async getAllGroups(): Promise<void> {
    try {
      const rows = await this.catalogClient('relations')
        .select('source_entity_ref', 'target_entity_ref')
        .where('type', 'childOf')
        .then();
      this.allRelations = rows;
    } catch (error) {
      const { token } = await this.tokenManager.getToken();
      const { items } = await this.catalogApi.getEntities(
        {
          filter: { kind: 'Group' },
          fields: ['metadata.name', 'metadata.namespace', 'spec.parent'],
        },
        { token },
      );
      this.allGroups = items;
    }
  }

  async getUserRelations(): Promise<Relation[]> {
    try {
      const rows = await this.catalogClient('relations')
        .select('source_entity_ref', 'target_entity_ref')
        .where({ type: 'memberOf', source_entity_ref: this.userEntityRef })
        .then();
      return rows;
    } catch (error) {
      console.log('error was thrown');
      return [];
    }
  }

  async getUserGroups(): Promise<Entity[]> {
    const { token } = await this.tokenManager.getToken();
    const { items } = await this.catalogApi.getEntities(
      {
        filter: { kind: 'Group', 'relations.hasMember': this.userEntityRef },
        fields: ['metadata.name', 'metadata.namespace', 'spec.parent'],
      },
      { token },
    );
    return items;
  }

  traverseGroups(memo: AncestorSearchMemo, group: Entity) {
    const groupsRefs = new Set<string>();
    const groupName = `group:${group.metadata.namespace?.toLocaleLowerCase(
      'en-US',
    )}/${group.metadata.name.toLocaleLowerCase('en-US')}`;
    if (!memo.hasEntityRef(groupName)) {
      memo.setNode(groupName);
    }

    const parent = group.spec?.parent as string;
    const parentGroup = this.allGroups.find(g => g.metadata.name === parent);

    if (parentGroup) {
      const parentName = `group:${group.metadata.namespace?.toLocaleLowerCase(
        'en-US',
      )}/${parent.toLocaleLowerCase('en-US')}`;
      memo.setEdge(parentName, groupName);
      groupsRefs.add(parentName);
    }

    if (groupsRefs.size > 0 && memo.isAcyclic()) {
      this.traverseGroups(memo, parentGroup!);
    }
  }

  traverseRelations(memo: AncestorSearchMemo, relation: Relation) {
    if (!memo.hasEntityRef(relation.source_entity_ref)) {
      memo.setNode(relation.source_entity_ref);
    }

    memo.setEdge(relation.target_entity_ref, relation.source_entity_ref);

    const parentGroup = this.allRelations.find(
      g => g.source_entity_ref === relation.target_entity_ref,
    );

    if (parentGroup && memo.isAcyclic()) {
      this.traverseRelations(memo, parentGroup!);
    }
  }

  async buildUserGraph(memo: AncestorSearchMemo) {
    if (this.allGroups.length > 0) {
      const userGroups = await this.getUserGroups();
      userGroups.forEach(group => this.traverseGroups(memo, group));
    } else {
      const userRelations = await this.getUserRelations();
      userRelations.forEach(group => this.traverseRelations(memo, group));
    }
  }
}
