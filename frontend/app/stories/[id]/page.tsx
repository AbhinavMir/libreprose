'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from "../../../components/ui/card"
import { Button } from "../../../components/ui/button"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "../../../components/ui/dialog"
import { Input } from "../../../components/ui/input"
import { Label } from "../../../components/ui/label"
import { Textarea } from "../../../components/ui/textarea"
import { useToast } from "../../../hooks/use-toast"
import Cookies from 'js-cookie'
import { useParams, useRouter } from 'next/navigation'
import debounce from 'lodash/debounce'

interface Story {
  id: string
  title: string
  description: string
  authorId: string
  createdAt: string
  updatedAt: string
}

interface Chapter {
  id: string
  title: string
  content: string
  storyId: string
  createdAt: string
  updatedAt: string
}

export default function StoryDetail() {
  const router = useRouter()
  const [story, setStory] = useState<Story | null>(null)
  const [chapters, setChapters] = useState<Chapter[]>([])
  const [selectedChapter, setSelectedChapter] = useState<Chapter | null>(null)
  const [newChapterTitle, setNewChapterTitle] = useState('')
  const [newChapterContent, setNewChapterContent] = useState('')
  const [isOpen, setIsOpen] = useState(false)
  const [isEditStoryOpen, setIsEditStoryOpen] = useState(false)
  const [isEditChapterOpen, setIsEditChapterOpen] = useState(false)
  const [editedStoryTitle, setEditedStoryTitle] = useState('')
  const [editedChapterTitle, setEditedChapterTitle] = useState('')
  const API_URL = "https://libreprose.onrender.com"
  const params = useParams()
  const storyId = params.id as string
  const { toast } = useToast()

  const updateChapter = async (chapterId: string, content?: string, title?: string, showToast: boolean = false) => {
    const token = Cookies.get('token')
    if (!token) return

    try {
      const response = await fetch(`${API_URL}/api/chapters/${chapterId}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          content: content ?? selectedChapter?.content,
          title: title ?? selectedChapter?.title
        })
      })
      const result = await response.json()
      if (result.status === 'success') {
        if (showToast) {
          toast({
            title: "Chapter updated",
            description: "Your changes have been saved"
          })
        }
        fetchStoryAndChapters()
        setIsEditChapterOpen(false)
      }
    } catch (err) {
      console.error('Failed to update chapter:', err)
      if (showToast) {
        toast({
          title: "Error",
          description: "Failed to save changes",
          variant: "destructive"
        })
      }
    }
  }

  const updateStoryTitle = async () => {
    const token = Cookies.get('token')
    if (!token) return

    try {
      const response = await fetch(`${API_URL}/api/stories/${storyId}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          title: editedStoryTitle
        })
      })
      const result = await response.json()
      if (result.status === 'success') {
        toast({
          title: "Story updated",
          description: "Title has been updated successfully"
        })
        setIsEditStoryOpen(false)
        fetchStoryAndChapters()
      }
    } catch (err) {
      console.error('Failed to update story:', err)
      toast({
        title: "Error",
        description: "Failed to update story title",
        variant: "destructive"
      })
    }
  }

  const debouncedUpdate = debounce((chapterId: string, content: string) => {
    updateChapter(chapterId, content, undefined, false)
  }, 1000)

  const handleContentChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const newContent = e.target.value
    const words = newContent.trim().split(/\s+/)
    
    if (selectedChapter) {
      // Update local state immediately
      setSelectedChapter({
        ...selectedChapter,
        content: newContent
      })
      
      // If word count is multiple of 5, trigger update
      if (words.length % 5 === 0) {
        debouncedUpdate(selectedChapter.id, newContent)
      }
    }
  }

  const handleSave = () => {
    if (selectedChapter) {
      updateChapter(selectedChapter.id, selectedChapter.content, undefined, true)
    }
  }

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        e.preventDefault()
        handleSave()
      }
    }
    
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [selectedChapter])

  const fetchStoryAndChapters = async () => {
    const token = Cookies.get('token')
    if (!token) return

    try {
      const storyResponse = await fetch(`${API_URL}/api/stories/${storyId}`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })
      const storyData = await storyResponse.json()
      if (storyData.status === 'success') {
        setStory(storyData.data)
        setEditedStoryTitle(storyData.data.title)
      }

      const chaptersResponse = await fetch(`${API_URL}/api/stories/${storyId}/chapters`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })
      const chaptersData = await chaptersResponse.json()
      if (chaptersData.status === 'success') {
        setChapters(chaptersData.data)
        if (chaptersData.data.length > 0 && !selectedChapter) {
          setSelectedChapter(chaptersData.data[0])
        }
      }
    } catch (err) {
      console.error('Failed to fetch story data:', err)
    }
  }

  useEffect(() => {
    fetchStoryAndChapters()
  }, [storyId])

  const handleCreateChapter = async () => {
    const token = Cookies.get('token')
    if (!token) return

    try {
      const response = await fetch(`${API_URL}/api/stories/${storyId}/chapters`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          title: newChapterTitle,
          content: newChapterContent
        })
      })
      const result = await response.json()
      if (result.status === 'success') {
        setIsOpen(false)
        setNewChapterTitle('')
        setNewChapterContent('')
        fetchStoryAndChapters()
      }
    } catch (err) {
      console.error('Failed to create chapter:', err)
    }
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    })
  }

  if (!story) {
    return <div className="container mx-auto p-4">Loading...</div>
  }

  return (
    <div className="flex h-screen">
      {/* Sidebar */}
      <div className="w-64 p-4 bg-gray-50">
        <div className="flex justify-between items-center mb-4">
          <Button variant="ghost" size="sm" onClick={() => router.push('/stories')}>Home</Button>
          <Dialog open={isOpen} onOpenChange={setIsOpen}>
            <DialogTrigger asChild>
              <Button variant="ghost" size="sm">Add</Button>
            </DialogTrigger>
            <DialogContent className="border-0 shadow-none">
              <DialogHeader>
                <DialogTitle>Create a New Chapter</DialogTitle>
              </DialogHeader>
              <div className="space-y-4">
                <div>
                  <Label htmlFor="title">Title</Label>
                  <Input
                    id="title"
                    value={newChapterTitle}
                    onChange={(e) => setNewChapterTitle(e.target.value)}
                    placeholder="Enter chapter title"
                    className="border-0 shadow-none"
                  />
                </div>
                <div>
                  <Label htmlFor="content">Content</Label>
                  <Textarea
                    id="content"
                    value={newChapterContent}
                    onChange={(e) => setNewChapterContent(e.target.value)}
                    placeholder="Enter chapter content"
                    className="h-40 border-0 shadow-none"
                  />
                </div>
                <Button onClick={handleCreateChapter} className="w-full border-0 shadow-none">
                  Create Chapter
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        </div>
        <div className="space-y-2">
          {chapters?.map((chapter) => (
            <div
              key={chapter.id}
              className={`p-2 rounded cursor-pointer hover:bg-gray-200 ${selectedChapter?.id === chapter.id ? 'bg-gray-200' : ''}`}
              onClick={() => setSelectedChapter(chapter)}
            >
              <h3 className="font-medium text-sm">{chapter.title}</h3>
              <p className="text-xs text-gray-500">{formatDate(chapter.createdAt)}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 p-4">
        <div className="mb-6">
          <div className="p-4 flex justify-between items-center">
            <h1 className="text-2xl font-bold">{story.title}</h1>
            <Dialog open={isEditStoryOpen} onOpenChange={setIsEditStoryOpen}>
              <DialogTrigger asChild>
                <Button variant="ghost" size="sm">Edit Story</Button>
              </DialogTrigger>
              <DialogContent className="border-0 shadow-none">
                <DialogHeader>
                  <DialogTitle>Edit Story Title</DialogTitle>
                </DialogHeader>
                <div className="space-y-4">
                  <div>
                    <Label htmlFor="storyTitle">Title</Label>
                    <Input
                      id="storyTitle"
                      value={editedStoryTitle}
                      onChange={(e) => setEditedStoryTitle(e.target.value)}
                      placeholder="Enter story title"
                      className="border-0 shadow-none"
                    />
                  </div>
                  <Button onClick={updateStoryTitle} className="w-full border-0 shadow-none">
                    Update Story
                  </Button>
                </div>
              </DialogContent>
            </Dialog>
          </div>
        </div>

        {selectedChapter ? (
          <div>
            <div className="flex flex-row justify-between items-center p-4">
              <div className="flex items-center gap-4">
                <h2 className="text-xl font-bold">{selectedChapter.title}</h2>
                <Dialog open={isEditChapterOpen} onOpenChange={setIsEditChapterOpen}>
                  <DialogTrigger asChild>
                    <Button variant="ghost" size="sm">Edit Title</Button>
                  </DialogTrigger>
                  <DialogContent className="border-0 shadow-none">
                    <DialogHeader>
                      <DialogTitle>Edit Chapter Title</DialogTitle>
                    </DialogHeader>
                    <div className="space-y-4">
                      <div>
                        <Label htmlFor="chapterTitle">Title</Label>
                        <Input
                          id="chapterTitle"
                          value={editedChapterTitle}
                          onChange={(e) => setEditedChapterTitle(e.target.value)}
                          placeholder="Enter chapter title"
                          className="border-0 shadow-none"
                        />
                      </div>
                      <Button 
                        onClick={() => updateChapter(selectedChapter.id, undefined, editedChapterTitle, true)} 
                        className="w-full border-0 shadow-none"
                      >
                        Update Chapter
                      </Button>
                    </div>
                  </DialogContent>
                </Dialog>
              </div>
              <Button onClick={handleSave} variant="ghost" size="sm">Save</Button>
            </div>
            <div className="p-4">
              <Textarea 
                value={selectedChapter.content}
                onChange={handleContentChange}
                className="min-h-[300px] w-full border-0 shadow-none resize-none focus:outline-none"
                placeholder="Brew some coffee and start writing..."
              />
              <p className="text-sm mt-4">Created: {formatDate(selectedChapter.createdAt)}</p>
            </div>
          </div>
        ) : (
          <div className="text-center text-gray-500 mt-8">
            Select a chapter to view its content
          </div>
        )}
      </div>
    </div>
  )
}