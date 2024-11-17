'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from "../../components/ui/card"
import { Button } from "../../components/ui/button"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "../../components/ui/dialog"
import { Input } from "../../components/ui/input"
import { Label } from "../../components/ui/label"
import { Textarea } from "../../components/ui/textarea"
import Cookies from 'js-cookie'
import { useRouter } from 'next/navigation'

interface Story {
  id: string
  title: string
  description: string
  authorId: string
  createdAt: string
  updatedAt: string
}

interface StoryData {
  story: Story
  chapterCount: number
}

export default function Component() {
  const [data, setData] = useState<StoryData[]>([])
  const [newTitle, setNewTitle] = useState('')
  const [newDescription, setNewDescription] = useState('')
  const [isOpen, setIsOpen] = useState(false)
  const [searchTerm, setSearchTerm] = useState('')
  const API_URL = process.env.API_URL || "http://localhost:8080"
  const router = useRouter()

  const fetchStories = async () => {
    const token = Cookies.get('token')
    if (!token) return

    try {
      const response = await fetch(`${API_URL}/api/stories`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })
      const stories = await response.json()
      if (stories.status === 'success') {
        setData(stories.data)
      }
    } catch (err) {
      console.error('Failed to fetch stories:', err)
    }
  }

  useEffect(() => {
    fetchStories()
  }, [])

  const handleCreateStory = async () => {
    const token = Cookies.get('token')
    if (!token) return

    try {
      const response = await fetch(`${API_URL}/api/stories`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          title: newTitle,
          description: newDescription
        })
      })
      const result = await response.json()
      if (result.status === 'success') {
        setIsOpen(false)
        setNewTitle('')
        setNewDescription('')
        fetchStories()
      }
    } catch (err) {
      console.error('Failed to create story:', err)
    }
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long', 
      day: 'numeric'
    })
  }
  const filteredData = data?.filter(item => 
    item.story.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
    item.story.description.toLowerCase().includes(searchTerm.toLowerCase())
  ) || []

  return (
    <div className="container mx-auto p-4">
      <div className="flex justify-between items-center mb-6">
        <Input
          type="search"
          placeholder="Search stories..."
          className="max-w-xs border-0 shadow-none bg-gray-50"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
        />
        <Dialog open={isOpen} onOpenChange={setIsOpen}>
          <DialogTrigger asChild>
            <Button variant="ghost">Create New Story</Button>
          </DialogTrigger>
          <DialogContent className="border-0 shadow-none">
            <DialogHeader>
              <DialogTitle>Create a New Story</DialogTitle>
            </DialogHeader>
            <div className="space-y-4">
              <div>
                <Label htmlFor="title">Title</Label>
                <Input
                  id="title"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  placeholder="Enter story title"
                  className="border-0 shadow-none"
                />
              </div>
              <div>
                <Label htmlFor="description">Description</Label>
                <Textarea
                  id="description"
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
                  placeholder="Enter story description"
                  className="border-0 shadow-none"
                />
              </div>
              <Button onClick={handleCreateStory} variant="ghost" className="w-full">
                Create Story
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <div className="space-y-4">
        {filteredData.length > 0 ? (
          filteredData.map((item) => (
            <div 
              key={item.story.id}
            onClick={() => router.push(`/stories/${item.story.id}`)}
            className="p-4 hover:bg-gray-50 cursor-pointer border-b"
          >
            <div className="flex justify-between items-start">
              <div>
                <h3 className="text-lg font-medium">{item.story.title}</h3>
                <p className="text-sm text-gray-500 mt-1">{item.story.description}</p>
              </div>
              <div className="text-sm text-gray-500 flex flex-col items-end">
                <span>{formatDate(item.story.createdAt)}</span>
                <span className="mt-1">{item.chapterCount} chapters</span>
              </div>
            </div>
            </div>
          ))
        ) : (
          <div className="text-center text-gray-500">No stories found</div>
        )}
      </div>
    </div>
  )
}