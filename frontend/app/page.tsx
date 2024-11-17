'use client'

import { Button } from "../components/ui/button"
import { ArrowRight, Download, Globe, Smartphone } from 'lucide-react'
import Link from "next/link"

export default function Component() {
  return (
    <div className="flex flex-col min-h-[100dvh]">
      <header className="p-4">
        <div className="flex items-center gap-2">
          <img src="https://web.archive.org/web/20090829093913im_/http://www.geocities.com/two4kat/guestbk-writing.gif" alt="Logo" className="w-10 h-10" />
          <h2 className="text-xl font-semibold">LibreProse</h2>
        </div>
      </header>
      <main className="flex-1 flex items-center justify-center">
        <section className="w-full py-12 md:py-24 lg:py-32 xl:py-48 font-serif">
          <div className="container mx-auto px-4 md:px-6">
            <div className="flex flex-col items-center space-y-4 text-center">
              <div className="space-y-2">
                <h1 className="text-3xl font-bold tracking-tighter sm:text-4xl md:text-5xl lg:text-6xl/none">
                  What if you could just write?
                </h1>
                <p className="mx-auto max-w-[700px] text-gray-500 md:text-xl">
                 The easiest tool to write a book.
                </p>
              </div>
              <div className="w-full max-w-sm space-y-2">
                <div className="grid grid-cols-3 gap-2">
                  <Button className="w-full" variant="outline" disabled title="Coming soon">
                    <Smartphone className="mr-2 h-4 w-4" />
                    Mobile
                  </Button>
                  <Button className="w-full" variant="outline" disabled title="Coming soon">
                    <Download className="mr-2 h-4 w-4" />
                    Desktop
                  </Button>
                  <Button className="w-full" variant="outline" onClick={() => window.location.href = '/login'}>
                    <Globe className="mr-2 h-4 w-4" />
                    Web
                  </Button>
                </div>
                <Button className="w-full">Get Started</Button>
              </div>
            </div>
          </div>
        </section>
      </main>
      <footer className="flex flex-col gap-2 sm:flex-row py-6 w-full shrink-0 items-center px-4 md:px-6 border-t">
        <p className="text-xs text-gray-500">© 2024 Acme Inc. All rights reserved.</p>
        <nav className="sm:ml-auto flex gap-4 sm:gap-6">
          <Link className="text-xs hover:underline underline-offset-4" href="#">
            Terms of Service
          </Link>
          <Link className="text-xs hover:underline underline-offset-4" href="#">
            Privacy
          </Link>
        </nav>
      </footer>
    </div>
  )
}