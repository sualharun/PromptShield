import React from 'react'
import { Slot } from '@radix-ui/react-slot'
import { cva } from 'class-variance-authority'
import { cn } from '../../lib/utils.js'

const buttonVariants = cva(
  'inline-flex items-center justify-center whitespace-nowrap text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ibm-blue-40 disabled:pointer-events-none disabled:opacity-50',
  {
    variants: {
      variant: {
        default: 'bg-ibm-blue-60 text-white hover:bg-ibm-blue-70',
        destructive: 'bg-ibm-red-60 text-white hover:bg-ibm-red-70',
        outline: 'border border-carbon-border bg-carbon-bg text-carbon-text hover:bg-carbon-layer',
        secondary: 'bg-carbon-layer text-carbon-text hover:bg-carbon-layer-2',
        ghost: 'hover:bg-carbon-layer hover:text-carbon-text',
        link: 'text-ibm-blue-40 underline-offset-4 hover:underline',
      },
      size: {
        default: 'h-10 px-4 py-2',
        sm: 'h-9 px-3',
        lg: 'h-11 px-8',
        icon: 'h-10 w-10',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  }
)

const Button = React.forwardRef(function Button(
  { className, variant, size, asChild = false, ...props },
  ref
) {
  const Comp = asChild ? Slot : 'button'
  return (
    <Comp
      className={cn(buttonVariants({ variant, size, className }))}
      ref={ref}
      {...props}
    />
  )
})

export { Button, buttonVariants }
