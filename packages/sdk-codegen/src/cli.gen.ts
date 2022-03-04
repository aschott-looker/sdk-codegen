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
import { CodeGen } from './codeGen'
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
  fileExtension = '.go'
  packagePath = ''

  keywords = new Set<string>([
    'break',
    'default',
    'func',
    'interface',
    'select',
    'case',
    'defer',
    'go',
    'map',
    'struct',
    'chan',
    'else',
    'goto',
    'package',
    'switch',
    'const',
    'fallthrough',
    'if',
    'range',
    'type',
    'continue',
    'for',
    'import',
    'return',
    'var',
  ])

  commandToSubCommands = new Map<string, Array<SubCommand>>()
  currentCommand = ''
  usedCommands = new Set<string>([])
  dedupe = 0

  constructor(public api: ApiModel, public versions?: IVersionInfo) {
    super(api, versions)
    this.packageName = `v${this.apiVersion.substring(
      0,
      this.apiVersion.indexOf('.')
    )}`
    this.apiVersion = this.packageName
  }

  supportsMultiApi(): boolean {
    return false
  }

  reserve(name: string) {
    if (this.keywords.has(name)) {
      return `_${name}`
    }
    return name
  }

  beginRegion(_indent: string, description: string): string {
    const [name, desc] = description.split(':').map((str) => str.trim())
    this.currentCommand = this.getUnusedCommandName(this.toCamelCase(name))
    return this.declareCobraCommand(this.currentCommand, name, desc)
  }

  declareCobraCommand(command: string, name: string, desc: string) {
    return [
      `var ${command} = &cobra.Command{`,
      `  Use:   "${name}",`,
      `  Short: "${desc}",`,
      `  Long:  "${desc}",`,
      `}`,
    ].join('\n')
  }

  endRegion(_indent: string, _description: string): string {
    return ''
  }

  declareMethod(indent: string, method: IMethod) {
    const name = this.toCamelCase(method.name)
    const commandName = this.getUnusedCommandName(name)
    const siblingCommands = this.commandToSubCommands.get(this.currentCommand)

    const flags = method.allParams.map((param) => {
      return new Flag(
        param.name,
        this.replaceAll(param.description, '"', '\\"'),
        param.required,
        this.getPFlag(param.type)
      )
    })
    const subCommand = new SubCommand(commandName, flags)
    if (siblingCommands !== undefined) {
      siblingCommands.push(subCommand)
    } else {
      this.commandToSubCommands.set(this.currentCommand, [subCommand])
    }

    const flagsCode = method.allParams
      .map((param) => this.declareParameter(indent, method, param))
      .join('\n')

    return this.declareRunnableCobraCommand(
      commandName,
      name,
      method.summary,
      this.replaceAll(method.description, '`', "'"),
      flagsCode,
      this.declareSdkCall(method, this.toCamelCaseCap(method.name))
    )
  }

  declareParameter(_indent: string, _method: IMethod, param: IParameter) {
    return [
      `    ${this.reserve(param.name)}, _ := cmd.Flags().Get${this.getPFlag(
        param.type
      )}("${param.name}")`,
      `    fmt.Println("${param.name} set to", ${this.reserve(param.name)})`,
    ].join('\n')
  }

  declareRunnableCobraCommand(
    command: string,
    name: string,
    short: string,
    long: string,
    flags: string,
    sdk: string
  ) {
    return [
      `var ${command} = &cobra.Command{`,
      `  Use:   "${name}",`,
      `  Short: "${short}",`,
      `  Long: \`${long}\`,`,
      `  Run: func(cmd *cobra.Command, args []string) {`,
      `${flags}`,
      `${sdk}`,
      `  },`,
      `}`,
    ].join('\n')
  }

  declareSdkCall(method: IMethod, requestType: string) {
    switch (method.httpMethod) {
      case 'POST': {
        return this.declarePostSdkCall(method, requestType)
      }
      case 'DELETE': {
        return this.declareDeleteSdkCall(method, requestType)
      }
      case 'PUT': {
        return this.declarePutSdkCall(method, requestType)
      }
      default: {
        if (requestType.includes('All')) {
          return this.declareGetAllSdkCall(method, requestType)
        } else {
          return this.declareGetSdkCall(method, requestType)
        }
      }
    }
  }

  declarePostSdkCall(method: IMethod, requestType: string) {
    if (requestType !== 'CreateUser') {
      return ''
    }
    const allParamsExceptBody = method.allParams.filter(
      (param) => param.name !== 'body'
    )
    const paramsStr = allParamsExceptBody
      .map((param) => {
        return `, ${this.reserve(param.name)}`
      })
      .join('')
    return [
      `    var request v4.Write${requestType.substring(6)}`,
      `    err := json.NewDecoder(strings.NewReader(body)).Decode(&request)`,
      `    if err != nil {`,
      `      fmt.Println("Error when decoding json")`,
      `    }`,
      `    response, err := sdk.${requestType}(request${paramsStr}, nil)`,
      `    if err != nil {`,
      `      fmt.Println("SDK failure:", err)`,
      `      return`,
      `    }`,
      `    res, _ := json.MarshalIndent(response, "", "  ")`,
      `    fmt.Println(string(res))`,
    ].join('\n')
  }

  declarePutSdkCall(method: IMethod, requestType: string) {
    if (requestType !== 'UpdateUser') {
      return ''
    }
    const idName = method.allParams[0].name
    const allParamsExceptBodyAndId = method.allParams.filter(
      (param) => param.name !== 'body' && param.name !== idName
    )
    const paramsStr = allParamsExceptBodyAndId
      .map((param) => {
        return `, ${this.reserve(param.name)}`
      })
      .join('')
    return [
      `    var request v4.Write${requestType.substring(6)}`,
      `    err := json.NewDecoder(strings.NewReader(body)).Decode(&request)`,
      `    if err != nil {`,
      `      fmt.Println("Error when decoding json")`,
      `    }`,
      ``,
      `    response, err := sdk.${requestType}(${idName}, request${paramsStr}, nil)`,
      `    if err != nil {`,
      `      fmt.Println("Error while calling API: ", err)`,
      `    }`,
      `    res, _ := json.MarshalIndent(response, "", "  ")`,
      `    fmt.Println(string(res))`,
    ].join('\n')
  }

  declareDeleteSdkCall(method: IMethod, requestType: string) {
    if (requestType !== 'DeleteUser') {
      return ''
    }
    const templateStr = method.allParams
      .map((param) => {
        return `${this.reserve(param.name)} ,`
      })
      .join('')
    return [
      `    response, err := sdk.${requestType}(${templateStr}nil)`,
      `    if err != nil {`,
      `      fmt.Println("Error while calling API: ", err)`,
      `    }`,
      `    res, _ := json.MarshalIndent(response, "", "  ")`,
      `    fmt.Println(string(res))`,
    ].join('\n')
  }

  declareGetSdkCall(method: IMethod, requestType: string) {
    if (requestType !== 'User') {
      return ''
    }
    const templateStr = method.allParams
      .map((param) => {
        return `${this.reserve(param.name)} ,`
      })
      .join('')
    return [
      `    response, err := sdk.${requestType}(${templateStr}nil)`,
      `    if err != nil {`,
      `      fmt.Println("Error while calling API: ", err)`,
      `    }`,
      `    res, _ := json.MarshalIndent(response, "", "  ")`,
      `    fmt.Println(string(res))`,
    ].join('\n')
  }

  declareGetAllSdkCall(method: IMethod, requestType: string) {
    if (requestType !== 'AllUsers') {
      return ''
    }
    const supportedParams = method.allParams.filter(
      (param) => param.name !== 'ids'
    )
    const templateStr = supportedParams
      .map((param) => {
        return `"${this.toCamelCaseCap(param.name)}": ${this.getFormatSpecifier(
          this.getPFlag(param.type)
        )}`
      })
      .join(', ')
    const valuesStr = supportedParams
      .map((param) => {
        return this.reserve(param.name)
      })
      .join(', ')
    return [
      `    var request v4.Request${requestType}`,
      `    formattedInput := fmt.Sprintf(\`{${templateStr}}\`, ${valuesStr})`,
      `    err := json.NewDecoder(strings.NewReader(formattedInput)).Decode(&request)`,
      `    if err != nil {`,
      `      fmt.Println("Failure to marshal input into model\\n", err)`,
      `      return`,
      `    }`,
      ``,
      `    response, err := sdk.${requestType}(request, nil)`,
      `    res, _ := json.MarshalIndent(response, "", "  ")`,
      `    fmt.Println(string(res))`,
    ].join('\n')
  }

  getFormatSpecifier(type: string) {
    switch (type) {
      case 'Bool': {
        return '%t'
      }
      case 'Int64': {
        return '%d'
      }
      default: {
        return '"%s"'
      }
    }
  }

  methodsPrologue(_indent: string) {
    return [
      `package cmd`,
      ``,
      `import (`,
      `  "encoding/json"`,
      `  "os"`,
      `  "fmt"`,
      `  "strings"`,
      ``,
      `  "github.com/looker-open-source/sdk-codegen/go/rtl"`,
      `  v4 "github.com/looker-open-source/sdk-codegen/go/sdk/v4"`,
      `  "github.com/spf13/cobra"`,
      `)`,
      ``,
      `var lookerIniPath = "./looker.ini"`,
      `var cfg, _ = rtl.NewSettingsFromFile(lookerIniPath, nil)`,
      `var sdk = v4.NewLookerSDK(rtl.NewAuthSession(cfg))`,
      ``,
      `var rootCmd = &cobra.Command{`,
      `  Use:   "looker-cli",`,
      `  Short: "Command line interface for interacting with a Looker instance.",`,
      `  Long:  "Command line interface for interacting with a Looker instance.",`,
      `}`,
      ``,
      `func Execute() {`,
      `  err := rootCmd.Execute()`,
      `  if err != nil {`,
      `    os.Exit(1)`,
      `  }`,
      `}`,
      ``,
    ].join('\n')
  }

  methodsEpilogue(_indent: string) {
    const addCommandsCode = Array.from(this.commandToSubCommands)
      .map(([mainCommand, subCommands]) => {
        const subCommandsString = subCommands
          .map((subCommand) => {
            const flagsCode = subCommand.flags
              .map((flag) => {
                if (flag.required) {
                  return this.declareRequiredCobraFlag(subCommand, flag)
                } else {
                  return this.declareCobraFlag(subCommand, flag)
                }
              })
              .join('\n')
            if (flagsCode === '') {
              return [
                `  ${mainCommand}.AddCommand(${subCommand.name})`,
                ``,
              ].join('\n')
            } else {
              return [
                `  ${mainCommand}.AddCommand(${subCommand.name})`,
                `${flagsCode}`,
                ``,
              ].join('\n')
            }
          })
          .join('')
        return [
          `${subCommandsString}  rootCmd.AddCommand(${mainCommand})`,
          ``,
        ].join('\n')
      })
      .join('')

    return [``, `func init() {`, `${addCommandsCode}}`, ``].join('\n')
  }

  declareCobraFlag(subCommand: SubCommand, flag: Flag) {
    return [
      `  ${subCommand.name}.Flags().${flag.type}("${
        flag.name
      }", ${flag.defaultValue()}, "${flag.description}")`,
    ].join('\n')
  }

  declareRequiredCobraFlag(subCommand: SubCommand, flag: Flag) {
    return [
      `  ${subCommand.name}.Flags().${flag.type}("${
        flag.name
      }", ${flag.defaultValue()}, "${flag.description}")`,
      `  cobra.MarkFlagRequired(${subCommand.name}.Flags(), "${flag.name}")`,
    ].join('\n')
  }

  declareProperty(_indent: string, _property: IProperty) {
    return ''
  }

  encodePathParams(_indent: string, _method: IMethod) {
    return ''
  }

  methodSignature(_indent: string, _method: IMethod) {
    return ''
  }

  modelsEpilogue(_indent: string) {
    return ''
  }

  modelsPrologue(_indent: string) {
    return ''
  }

  summary(_indent: string, _text: string) {
    return ''
  }

  typeSignature(_indent: string, _type: IType) {
    return ''
  }

  getUnusedCommandName(command: string) {
    command = `${command}Cmd`
    if (this.usedCommands.has(command)) {
      command = `${command}${this.dedupe++}`
    }
    this.usedCommands.add(command)
    return command
  }

  getPFlag(type: IType): string {
    switch (type.name) {
      case 'boolean': {
        return 'Bool'
      }
      case 'double': {
        return 'Float64'
      }
      case 'float': {
        return 'Float32'
      }
      case 'int32': {
        return 'Int32'
      }
      case 'int64': {
        return 'Int64'
      }
      case 'integer': {
        return 'Int'
      }
      case 'number': {
        return 'Float64'
      }
      default: {
        return 'String'
      }
    }
  }

  replaceAll(str: string, find: string, replace: string) {
    return str.replace(new RegExp(find, 'g'), replace)
  }

  capitalize(str: string): string {
    return str.charAt(0).toUpperCase() + str.slice(1)
  }

  toCamelCaseCap(str: string): string {
    return this.capitalize(
      str.replace(/([-_][a-z])/g, (group) =>
        group.toUpperCase().replace('-', '').replace('_', '')
      )
    )
  }

  toCamelCase(str: string): string {
    return str.replace(/([-_][a-z])/g, (group) =>
      group.toUpperCase().replace('-', '').replace('_', '')
    )
  }
}

class SubCommand {
  name = ''
  flags = new Array<Flag>()

  constructor(name: string, flags: Array<Flag>) {
    this.name = name
    this.flags = flags
  }
}

class Flag {
  name = ''
  description = ''
  required = false
  type = ''

  constructor(
    name: string,
    description: string,
    required: boolean,
    type: string
  ) {
    this.name = name
    this.description = description
    this.required = required
    this.type = type
  }

  defaultValue() {
    if (this.type === 'Bool') {
      return false
    } else if (this.type === 'Int64') {
      return 0
    } else {
      return '""'
    }
  }
}
