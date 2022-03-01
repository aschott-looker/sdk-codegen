/*

 MIT License

 Copyright (c) 2021 Looker Data Sciences, Inc.

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.

 */

import type { IVersionInfo } from './codeGen'
import { CodeGen, commentBlock } from './codeGen'
import type {
  ApiModel,
  IMethod,
  IParameter,
  IProperty,
  IType,
} from './sdkModels'

/**
 * CLI generator
 */
export class CliGen extends CodeGen {
  codePath = './cli'
  fileExtension = '.cli'
  nullStr = 'nil'
  packagePath = ''
  commentStr = '// '

  enumDelimiter = '\n'
  indentStr = '  '
  endTypeStr = '}'
  codeQuote = `"`

  useNamedParameters = false
  needsRequestTypes = true

  keywords = new Set<string>([])

  constructor(public api: ApiModel, public versions?: IVersionInfo) {
    super(api, versions)
    this.packageName = `v${this.apiVersion.substring(
      0,
      this.apiVersion.indexOf('.')
    )}`
    this.apiVersion = this.packageName
  }

  declareMethod(indent: string, method: IMethod) {
    return `${indent}${method.name}`
  }

  declareParameter(indent: string, method: IMethod, param: IParameter) {
    const mapped = this.paramMappedType(param, method)
    return `${indent}${param.name}: ${mapped.name}`
  }

  declareProperty(indent: string, property: IProperty) {
    const type = this.typeMap(property.type)
    return `${indent}var ${property.name}: ${type.name}`
  }

  encodePathParams(indent: string, method: IMethod) {
    let encodings = ''
    if (method.pathParams.length > 0) {
      for (const param of method.pathParams) {
        encodings += `${indent}val path_${param.name} = encodeParam(${param.name})\n`
      }
    }
    return encodings
  }

  methodSignature(indent: string, method: IMethod) {
    return this.declareMethod(indent, method)
  }

  methodsEpilogue(_indent: string) {
    return '\n}'
  }

  methodsPrologue(_indent: string) {
    return ''
  }

  modelsEpilogue(_indent: string) {
    return ''
  }

  modelsPrologue(_indent: string) {
    return ''
  }

  summary(indent: string, text: string) {
    return this.commentHeader(indent, text)
  }

  commentHeader(indent: string, text: string | undefined, commentStr = ' * ') {
    if (commentStr === ' ') {
      return `${indent}/**\n\n${commentBlock(
        text,
        indent,
        commentStr
      )}\n${indent} */\n`
    }
    return `${indent}/**\n${commentBlock(
      text,
      indent,
      commentStr
    )}\n${indent} */\n`
  }

  typeSignature(indent: string, type: IType) {
    return `
${this.commentHeader(indent, type.description).trim()}
${indent}data class ${type.name} (
`.trim()
  }
}
