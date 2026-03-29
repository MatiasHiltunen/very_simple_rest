import openapi from '../../openapi.json';

type OperationLike = {
  summary?: string;
  operationId?: string;
};

type PathMap = Record<string, Record<string, OperationLike>>;

export interface ApiOperation {
  method: string;
  path: string;
  summary: string;
}

const paths = openapi.paths as PathMap;

export const apiOperations: ApiOperation[] = Object.entries(paths)
  .flatMap(([path, methods]) =>
    Object.entries(methods).map(([method, operation]) => ({
      method: method.toUpperCase(),
      path,
      summary: operation.summary ?? operation.operationId ?? 'Operation',
    })),
  )
  .sort((left, right) => left.path.localeCompare(right.path) || left.method.localeCompare(right.method));

export function getOperationsForResource(resourcePath: string): ApiOperation[] {
  const basePath = `/${resourcePath}`;
  return apiOperations.filter(
    (operation) =>
      operation.path === basePath ||
      operation.path.startsWith(`${basePath}/`) ||
      operation.path.startsWith(`${basePath}/{`),
  );
}

export function formatMethodLabel(method: string): string {
  switch (method) {
    case 'GET':
      return 'Read';
    case 'POST':
      return 'Create';
    case 'PUT':
      return 'Replace';
    case 'PATCH':
      return 'Update';
    case 'DELETE':
      return 'Delete';
    default:
      return method;
  }
}
