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

  regionToSubCommands = new Map<string, Array<SubCommand>>()
  currentRegion = ''
  commands = new Set<string>([])

  constructor(public api: ApiModel, public versions?: IVersionInfo) {
    super(api, versions)
    this.packageName = `v${this.apiVersion.substring(
      0,
      this.apiVersion.indexOf('.')
    )}`
    this.apiVersion = this.packageName
  }

  beginRegion(_indent: string, description: string): string {
    const [name, desc] = description.split(':').map((str) => str.trim())
    const camelCaseName = name.charAt(0).toLowerCase() + name.slice(1)
    this.currentRegion = `${camelCaseName}Cmd`
    if (this.commands.has(this.currentRegion)) {
      this.currentRegion = `${this.currentRegion}${this.getRandomInt(10000)}`
    }
    this.commands.add(this.currentRegion)
    return `
var ${this.currentRegion} = &cobra.Command{
  Use:   "${name}",
  Short: "${desc}",
  Long: "${desc}",
}`
  }

  getRandomInt(max: number) {
    return Math.floor(Math.random() * max)
  }

  endRegion(_indent: string, _description: string): string {
    return ''
  }

  getMappedType(type: IType): string {
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

  declareMethod(_indent: string, method: IMethod) {
    let commandName = method.name
    const underScoreIndexes = this.getAllIndexes(commandName, '_')
    underScoreIndexes.forEach((index) => {
      commandName = this.replaceAt(
        commandName,
        index + 1,
        commandName[index + 1].toUpperCase()
      )
    })
    const use = this.replaceAll(commandName, '_', '')
    commandName = `${use}Cmd`
    if (this.commands.has(commandName)) {
      commandName = `${commandName}${this.getRandomInt(10000)}`
    }
    this.commands.add(commandName)
    const subCommands = this.regionToSubCommands.get(this.currentRegion)
    const flagObjs = method.allParams.map((param) =>
      this.generateFlagObj(param)
    )
    const subCommand = new SubCommand(commandName, flagObjs)
    if (subCommands !== undefined) {
      subCommands.push(subCommand)
    } else {
      this.regionToSubCommands.set(this.currentRegion, [subCommand])
    }
    const flags = method.allParams
      .map((param) => this.generateFlag(param))
      .join('\n')
    return `
var ${commandName} = &cobra.Command{
  Use:   "${use}",
  Short: "${method.summary}",
  Long: \`${this.replaceAll(method.description, '`', "'")}\`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("${use} called")
    ${flags}
  },
}`
  }

  generateFlag(param: IParameter) {
    return `
    ${param.name}, _ := cmd.Flags().Get${this.getMappedType(param.type)}("${
      param.name
    }")
    fmt.Println("${param.name} set to ", ${param.name})`
  }

  generateFlagObj(param: IParameter) {
    return new Flag(
      param.name,
      param.description,
      param.required,
      this.getMappedType(param.type)
    )
  }

  replaceAll(str: string, find: string, replace: string) {
    return str.replace(new RegExp(find, 'g'), replace)
  }

  replaceAt(str: string, index: number, replacement: string) {
    return (
      str.substr(0, index) +
      replacement +
      str.substr(index + replacement.length)
    )
  }

  getAllIndexes(str: string, val: string) {
    const indexes = []
    let i
    for (i = 0; i < str.length; i++) if (str[i] === val) indexes.push(i)
    return indexes
  }

  declareParameter(_indent: string, _method: IMethod, _param: IParameter) {
    return ''
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

  methodsEpilogue(indent: string) {
    const addCommands = Array.from(this.regionToSubCommands)
      .map(([key, subCommands]) => {
        const mainCommand = key
        const subCommandsString = subCommands
          .map((subCommand) => {
            const flags = subCommand.flags
              .map((flag) => {
                let requiredText = ''
                if (flag.required) {
                  requiredText = `cobra.MarkFlagRequired(${subCommand.name}.Flags(), "${flag.name}")`
                }
                return `
              ${subCommand.name}.Flags().${flag.type}("${flag.name}", "${
                  flag.shortName
                }", ${flag.defaultValue()}, "${flag.description}")
              ${requiredText}
              `
              })
              .join('\n')
            return `
            ${indent}${mainCommand}.AddCommand(${subCommand.name})
            ${flags}
            `
          })
          .join('\n')
        return `\n${subCommandsString}\n${indent}rootCmd.AddCommand(${mainCommand})`
      })
      .join('')

    return `
func init() {
${addCommands}
}`
  }

  methodsPrologue(_indent: string) {
    return `
package cmd

import (
  "fmt"

  "github.com/spf13/cobra"
)`
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

  commentHeader(
    _indent: string,
    _text: string | undefined,
    _commentStr = ' * '
  ) {
    return ''
  }

  typeSignature(_indent: string, _type: IType) {
    return ''
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
  shortName = ''
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
    this.shortName = name
      .split('_')
      .map((part) => part.charAt(0))
      .join('')
    this.description = description
    this.required = required
    if (type === 'Bool') {
      this.type = 'BoolP'
    } else {
      this.type = type
    }
  }

  defaultValue() {
    if (this.type === 'BoolP') {
      return false
    } else if (this.type === 'Int64') {
      return 0
    } else {
      return '""'
    }
  }
}
