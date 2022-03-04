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
  supportedRequestTypes = new Set<string>([
    'CreateUser',
    'UpdateUser',
    'DeleteUser',
    'AllUsers',
    'User',
  ])

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

  isSupported(requestType: string) {
    return this.supportedRequestTypes.has(requestType)
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

    const requestType = this.toCamelCaseCap(method.name)

    let flagsCode = method.allParams
      .filter((param) => param.name !== 'ids')
      .map((param) => {
        return this.declareParameter(indent, method, param)
      })
      .join('\n')

    if (!this.isSupported(requestType)) {
      flagsCode = ''
    }

    return this.declareRunnableCobraCommand(
      commandName,
      name,
      method.summary,
      this.replaceAll(method.description, '`', "'"),
      flagsCode,
      this.declareSdkCall(method, requestType)
    )
  }

  declareParameter(_indent: string, _method: IMethod, param: IParameter) {
    return [
      `    ${this.reserve(param.name)}, _ := cmd.Flags().Get${this.getPFlag(
        param.type
      )}("${param.name}")`,
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
    if (!this.isSupported(requestType)) {
      return ''
    }
    switch (method.httpMethod) {
      case 'POST': {
        return this.declarePostSdkCall(method, requestType)
      }
      case 'DELETE': {
        return this.declareDeleteSdkCall(method, requestType)
      }
      case 'PATCH':
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
    const allParamsExceptBody = method.allParams.filter(
      (param) => param.name !== 'body'
    )
    const paramsStr = allParamsExceptBody
      .map((param) => {
        return `, ${this.reserve(param.name)}`
      })
      .join('')
    return [
      `    var cfg, _ = rtl.NewSettingsFromFile(lookerIniPath, nil)`,
      `    var sdk = v4.NewLookerSDK(rtl.NewAuthSession(cfg))`,
      `    var request v4.Write${requestType.substring(6)}`,
      `    json.NewDecoder(strings.NewReader(body)).Decode(&request)`,
      `    response, _ := sdk.${requestType}(request${paramsStr}, nil)`,
      `    jsonResponse, _ := json.MarshalIndent(response, "", "  ")`,
      `    fmt.Println(string(jsonResponse))`,
    ].join('\n')
  }

  declarePutSdkCall(method: IMethod, requestType: string) {
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
      `    var cfg, _ = rtl.NewSettingsFromFile(lookerIniPath, nil)`,
      `    var sdk = v4.NewLookerSDK(rtl.NewAuthSession(cfg))`,
      `    var request v4.Write${requestType.substring(6)}`,
      `    json.NewDecoder(strings.NewReader(body)).Decode(&request)`,
      `    response, _ := sdk.${requestType}(${idName}, request${paramsStr}, nil)`,
      `    jsonResponse, _ := json.MarshalIndent(response, "", "  ")`,
      `    fmt.Println(string(jsonResponse))`,
    ].join('\n')
  }

  declareDeleteSdkCall(method: IMethod, requestType: string) {
    const templateStr = method.allParams
      .map((param) => {
        return `${this.reserve(param.name)} ,`
      })
      .join('')
    return [
      `    var cfg, _ = rtl.NewSettingsFromFile(lookerIniPath, nil)`,
      `    var sdk = v4.NewLookerSDK(rtl.NewAuthSession(cfg))`,
      `    response, _ := sdk.${requestType}(${templateStr}nil)`,
      `    jsonResponse, _ := json.MarshalIndent(response, "", "  ")`,
      `    fmt.Println(string(jsonResponse))`,
    ].join('\n')
  }

  declareGetSdkCall(method: IMethod, requestType: string) {
    const templateStr = method.allParams
      .map((param) => {
        return `${this.reserve(param.name)} ,`
      })
      .join('')
    return [
      `    var cfg, _ = rtl.NewSettingsFromFile(lookerIniPath, nil)`,
      `    var sdk = v4.NewLookerSDK(rtl.NewAuthSession(cfg))`,
      `    response, _ := sdk.${requestType}(${templateStr}nil)`,
      `    jsonResponse, _ := json.MarshalIndent(response, "", "  ")`,
      `    fmt.Println(string(jsonResponse))`,
    ].join('\n')
  }

  declareGetAllSdkCall(method: IMethod, requestType: string) {
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
      `    var cfg, _ = rtl.NewSettingsFromFile(lookerIniPath, nil)`,
      `    var sdk = v4.NewLookerSDK(rtl.NewAuthSession(cfg))`,
      `    var request v4.Request${requestType}`,
      `    formattedInput := fmt.Sprintf(\`{${templateStr}}\`, ${valuesStr})`,
      `    json.NewDecoder(strings.NewReader(formattedInput)).Decode(&request)`,
      `    response, _ := sdk.${requestType}(request, nil)`,
      `    jsonResponse, _ := json.MarshalIndent(response, "", "  ")`,
      `    fmt.Println(string(jsonResponse))`,
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
      `  "strconv"`,
      `  "bufio"`,
      ``,
      `  "github.com/looker-open-source/sdk-codegen/go/rtl"`,
      `  v4 "github.com/looker-open-source/sdk-codegen/go/sdk/v4"`,
      `  "github.com/spf13/cobra"`,
      `)`,
      ``,
      `const (`,
      `  apiVersionKey   = "api_versions"`,
      `  baseUrlKey      = "base_url"`,
      `  clientIdKey     = "client_id"`,
      `  clientSecretKey = "client_secret"`,
      `  verifySslKey    = "verify_ssl"`,
      `  timeoutKey      = "timeout"`,
      `)`,
      ``,
      `var lookerIniPath = "./looker.ini"`,
      ``,
      `var rootCmd = &cobra.Command{`,
      `  Use:   "looker-cli",`,
      `  Short: "Command line interface for interacting with a Looker instance.",`,
      `  Long:  "Command line interface for interacting with a Looker instance.",`,
      `}`,
      ``,
      `var lookerInitCmd = &cobra.Command {`,
      `  Use: "init",`,
      `  Short: "Command line prompts to generate looker.ini.",`,
      `  Long: "Command line prompts to generate looker.ini.  Will overwrite existing files.",`,
      `  Run: func(cmd *cobra.Command, args []string) {`,
      `    file := getFile(lookerIniPath)`,
      `    defer file.Close()`,
      `    `,
      `    reader := bufio.NewReader(os.Stdin)`,
      `    apiV := prompt(reader, apiVersionKey, "3.1,4.0")`,
      `    baseUrl := prompt(reader, baseUrlKey, "")`,
      `    clientId := prompt(reader, clientIdKey, "")`,
      `    clientSecret := prompt(reader, clientSecretKey, "")`,
      `    verifySsl, _ := strconv.ParseBool(prompt(reader, verifySslKey, "true"))`,
      `    timeout, _ := strconv.Atoi(prompt(reader, timeoutKey, "120"))`,
      `    `,
      `    fileContent := fmt.Sprintf("[Looker]\\n%s=%s\\n%s=%s\\n%s=%s\\n%s=%s\\n%s=%t\\n%s=%d", apiVersionKey, apiV, baseUrlKey, baseUrl, clientIdKey, clientId, clientSecretKey, clientSecret, verifySslKey, verifySsl, timeoutKey, timeout)`,
      `    file.WriteString(fileContent)`,
      `    file.Sync()`,
      `  },`,
      `}`,
      ``,
      `func prompt(reader *bufio.Reader, text string, defaultValue string) string {`,
      `  defaultMessage := " (no default value, required)"`,
      `  if defaultValue != "" {`,
      `    defaultMessage = fmt.Sprintf(" (leave empty for default %s)", defaultValue)`,
      `  }`,
      `  fmt.Printf(text + defaultMessage + ":")`,
      `  value, _ := reader.ReadString('\\n')`,
      `  value = strings.TrimSpace(value)`,
      `  if value == "" {`,
      `    return defaultValue`,
      `  }`,
      `  return value`,
      `}`,
      ``,
      `func getFile(fileName string) *os.File {`,
      `  if _, err := os.Stat(fileName); err != nil {`,
      `    file, _ := os.Create(fileName)`,
      `    return file`,
      `  } else {`,
      `    file, err := os.OpenFile(fileName, os.O_WRONLY, 0644)`,
      `    if err != nil {`,
      `      panic(any(err))`,
      `    }`,
      `    return file`,
      `  }`,
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

    return [
      ``,
      `func init() {`,
      `  rootCmd.AddCommand(lookerInitCmd)`,
      `${addCommandsCode}}`,
      ``,
    ].join('\n')
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
    return '//go:build ignore'
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
